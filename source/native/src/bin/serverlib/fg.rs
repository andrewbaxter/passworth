//! "Foreground" (user-facing) operations: unlocking, initializing credentials, and
//! access prompts. All credential logic lives here in the server; the windows
//! themselves are shown by the `passworth-ui` helper process via `UiClient`.
use {
    crate::{
        FactorTree,
        FactorTreeVariant,
    },
    flowcontrol::shed,
    loga::{
        DebugDisplay,
        Log,
        ResultContext,
        ea,
    },
    openpgp_card_sequoia::state::Open,
    passworth_native::{
        config::latest::ConfigCredSmartcards,
        crypto::{
            CardStream,
            KDF_SALT_LEN,
            TokenScheme,
            and_token,
            db_key,
            get_card_pubkey,
            kdf_token,
            local_decrypt,
            local_encrypt,
            self,
        },
        error::{
            ToUiErr,
            UiErr,
        },
        generate,
        uiproto::{
            Body,
            Title,
            UiValue,
        },
    },
    rand::{
        RngCore,
        rng,
    },
    rusqlite::Connection,
    sequoia_openpgp::serialize::stream::{
        Encryptor2,
        LiteralWriter,
        Message,
        Recipient,
    },
    std::{
        collections::{
            HashMap,
            HashSet,
            hash_map::Entry,
        },
        future::Future,
        io::Write,
        path::PathBuf,
        sync::{
            Arc,
            Mutex,
        },
        time::{
            Duration,
            Instant,
        },
    },
    super::{
        dbutil::open_privdb,
        privdb,
        uiclient::{
            UiClient,
            UiSpawnConfig,
        },
    },
    tokio::select,
};

pub enum B2F {
    Initialize(B2FInitialize, tokio::sync::oneshot::Sender<Result<Option<B2FInitializeResult>, loga::Error>>),
    Prompt(B2FPrompt, tokio::sync::oneshot::Sender<Result<Option<bool>, loga::Error>>),
    Unlock(B2FUnlock, tokio::sync::oneshot::Sender<Result<Option<B2FUnlockResult>, loga::Error>>),
}

pub struct B2FInitialize {
    pub prev_root_factor: Option<Arc<FactorTree>>,
    /// Scheme the previous tree's tokens/state were produced with.
    pub prev_scheme: TokenScheme,
    pub prev_state: HashMap<String, Vec<u8>>,
    pub prev_tokens: HashMap<String, Vec<u8>>,
    pub root_factor: Arc<FactorTree>,
    pub state_changed: HashSet<String>,
    pub tokens_changed: HashSet<String>,
}

pub struct B2FInitializeResult {
    pub root_token: Option<String>,
    pub store_state: HashMap<String, Vec<u8>>,
}

pub struct B2FPrompt {
    pub prompt_rules: HashMap<usize, (String, u64)>,
    /// Description of the requesting process.
    pub principal: String,
    /// Paths being accessed.
    pub paths: Vec<String>,
}

pub struct B2FUnlock {
    pub privdb_path: PathBuf,
    /// If true, fail rather than silently creating a new empty database when the file
    /// is missing.
    pub require_exists: bool,
    pub root_factor: Arc<FactorTree>,
    pub scheme: TokenScheme,
    pub state: HashMap<String, Vec<u8>>,
}

pub struct B2FUnlockResult {
    pub privdbc: Connection,
    /// The sqlcipher key string the database was opened with.
    pub root_token: String,
    /// Factor tokens, under the scheme the unlock was performed with.
    pub tokens: HashMap<String, Vec<u8>>,
}

pub struct FgState {
    pub last_prompts: Mutex<HashMap<usize, Instant>>,
    pub log: Log,
    pub ui_config: UiSpawnConfig,
}

// UI helpers
//
// `Ok(None)` means the user cancelled; a helper process failure is
// `InternalUnresolvable`.
async fn ask(ui: &UiClient, title: Title, error: Option<String>, body: Body) -> Result<Option<UiValue>, UiErr> {
    let mut w = ui.open(title, error, body);
    return Ok(w.wait().await.map_err(|e| UiErr::InternalUnresolvable(e))?);
}

fn protocol_err(v: UiValue, expected: &str) -> UiErr {
    return UiErr::InternalUnresolvable(
        loga::err_with("UI helper returned an unexpected value type", ea!(expected = expected, got = v.dbg_str())),
    );
}

fn expect_bytes(v: UiValue) -> Result<Vec<u8>, UiErr> {
    match v {
        UiValue::Bytes(b) => return Ok(b),
        v => return Err(protocol_err(v, "bytes")),
    }
}

fn expect_text(v: UiValue) -> Result<String, UiErr> {
    match v {
        UiValue::Text(t) => return Ok(t),
        v => return Err(protocol_err(v, "text")),
    }
}

fn expect_index(v: UiValue) -> Result<usize, UiErr> {
    match v {
        UiValue::Index(i) => return Ok(i),
        v => return Err(protocol_err(v, "index")),
    }
}

fn expect_bool(v: UiValue) -> Result<bool, UiErr> {
    match v {
        UiValue::Bool(b) => return Ok(b),
        v => return Err(protocol_err(v, "bool")),
    }
}

async fn ui_choose(
    ui: &UiClient,
    error: Option<String>,
    title: Title,
    choices: &Vec<Arc<FactorTree>>,
) -> Result<Option<Arc<FactorTree>>, UiErr> {
    let Some(v) = ask(ui, title, error, Body::Choose {
        message: "Choose an unlock method.".to_string(),
        options: choices.iter().map(|c| c.desc.clone()).collect(),
    }).await? else {
        return Ok(None);
    };
    let i = expect_index(v)?;
    let Some(c) = choices.get(i) else {
        return Err(UiErr::InternalUnresolvable(loga::err_with("UI helper returned out of range choice", ea!(index = i))));
    };
    return Ok(Some(c.clone()));
}

async fn ui_recovery_entry(
    ui: &UiClient,
    error: Option<String>,
    title: Title,
    message: &str,
) -> Result<Option<Vec<u8>>, UiErr> {
    let Some(v) = ask(ui, title, error, Body::EnterPhrase { message: message.to_string() }).await? else {
        return Ok(None);
    };
    return Ok(Some(expect_bytes(v)?));
}

/// Show a message until a card is presented (or the user cancels).
async fn ui_get_smartcard(
    ui: &UiClient,
    card_stream: &mut CardStream,
    error: Option<String>,
    title: Title,
    fingerprints: &[&str],
) -> Result<Option<openpgp_card_sequoia::Card<Open>>, UiErr> {
    let mut message = "Insert or swipe smartcard with GPG fingerprint:".to_string();
    for fingerprint in fingerprints {
        message.push_str(&format!("\n • {}", fingerprint));
    }
    let mut w = ui.open(title, error, Body::Message { message: message });
    select!{
        r = w.wait() => {
            r.map_err(|e| UiErr::InternalUnresolvable(e))?;
            return Ok(None);
        },
        c = card_stream.next() => {
            return Ok(c);
        },
    }
}

/// Derive a V2 token from user-entered material using the per-factor salt stored in
/// the factor's state.
fn derive_entered_prev(
    scheme: TokenScheme,
    prev_state: &HashMap<String, Vec<u8>>,
    id: &str,
    entered: Vec<u8>,
) -> Result<Vec<u8>, UiErr> {
    match scheme {
        TokenScheme::Legacy => return Ok(entered),
        TokenScheme::V2 => {
            let salt =
                prev_state
                    .get(id)
                    .context_with("Salt for factor missing in database", ea!(factor = id))?;
            return Ok(kdf_token(&entered, salt)?);
        },
    }
}

/// Derive a fresh V2 token from user-entered material, generating and returning a new
/// salt to be stored as the factor's state.
fn derive_entered_new(entered: &[u8]) -> Result<(Vec<u8>, Vec<u8>), UiErr> {
    let salt = generate::gen_bytes(KDF_SALT_LEN);
    let token = kdf_token(entered, &salt)?;
    return Ok((token, salt));
}

async fn do_creds(
    ui: &UiClient,
    state: Arc<FgState>,
    token_changed: HashSet<String>,
    state_changed: HashSet<String>,
    mut prev_tokens: HashMap<String, Vec<u8>>,
    prev_state: HashMap<String, Vec<u8>>,
    mut show_error: Option<String>,
    prev_scheme: TokenScheme,
    start: Either,
) -> Result<Option<DoCredsRes>, UiErr> {
    let mut stack = vec![(start, true)];
    let mut new_tokens = HashMap::<String, Vec<u8>>::new();
    let mut store_state = HashMap::<String, Vec<u8>>::new();
    while let Some((at, descending)) = stack.pop() {
        match &at {
            Either::New(new, old) => {
                let log = state.log.fork(ea!(factor = new.id));
                let prev_variant = old.as_ref().map(|x| &x.variant);
                if new_tokens.contains_key(&new.id) {
                    // nop
                } else if Some(new) == old.as_ref() && !token_changed.contains(&new.id) {
                    if let Some(token) = prev_tokens.get(&new.id) {
                        new_tokens.insert(new.id.clone(), token.clone());
                    } else {
                        stack.push((Either::New(new.clone(), old.clone()), true));
                        stack.push((Either::Prev(new.clone()), true));
                    }
                } else {
                    match &new.variant {
                        FactorTreeVariant::And(children) => {
                            if descending {
                                stack.push((at.clone(), false));
                                let mut match_old = HashMap::new();
                                if let Some(FactorTreeVariant::And(prev_children)) = prev_variant {
                                    for child in prev_children {
                                        match_old.insert(child.id.clone(), child.clone());
                                    }
                                }
                                for child in children.iter().rev() {
                                    if new_tokens.contains_key(&child.id) {
                                        continue;
                                    }
                                    stack.push((Either::New(child.clone(), match_old.remove(&child.id)), true));
                                }
                            } else {
                                let token =
                                    and_token(
                                        TokenScheme::V2,
                                        &children
                                            .iter()
                                            .map(|child| new_tokens.get(&child.id).unwrap().as_slice())
                                            .collect::<Vec<_>>(),
                                    );
                                new_tokens.insert(new.id.clone(), token);
                            }
                        },
                        FactorTreeVariant::Or(children) => {
                            if descending {
                                stack.push((at.clone(), false));
                                let mut match_old = HashMap::new();
                                if let Some(FactorTreeVariant::Or(prev_children)) = prev_variant {
                                    for child in prev_children {
                                        match_old.insert(child.id.clone(), child.clone());
                                    }
                                }
                                for child in children.iter().rev() {
                                    if
                                    // Need to generate sub-state for this child
                                    token_changed.contains(&child.id) ||
                                        // Need to descend so child can regen its own state
                                        state_changed.contains(&child.id) {
                                        stack.push(
                                            (Either::New(child.clone(), match_old.remove(&child.id)), true),
                                        );
                                    }
                                }
                                if let Some(FactorTreeVariant::Or(prev_children)) = prev_variant {
                                    let mut already_unlocked = false;
                                    for child in prev_children {
                                        if prev_tokens.contains_key(&child.id) {
                                            already_unlocked = true;
                                        }
                                    }
                                    if !already_unlocked {
                                        let Some(child) =
                                            ui_choose(
                                                ui,
                                                show_error.take(),
                                                Title::Unlock(new.desc.to_string()),
                                                &prev_children,
                                            ).await? else {
                                                return Ok(None);
                                            };
                                        stack.push((Either::Prev(child), true));
                                    }
                                }
                            } else {
                                // Get or token
                                let token = shed!{
                                    'found _;
                                    if let Some(FactorTreeVariant::Or(prev_children)) = prev_variant {
                                        for child in prev_children {
                                            if let Some(key) = prev_tokens.get(&child.id) {
                                                break 'found local_decrypt(
                                                    &key,
                                                    prev_state
                                                        .get(&new.id)
                                                        .stack_context(&log, "Missing state for or")?,
                                                )
                                                    .stack_context(
                                                        &log,
                                                        "Error reading existing encrypted factor data",
                                                    )?
                                                    .stack_context(
                                                        &log,
                                                        "Unexpected error: token used for unlock failed during new-token generation",
                                                    )?;
                                            }
                                        }
                                    }
                                    break 'found gen_token();
                                };
                                let mut state = match prev_state.get(&new.id) {
                                    Some(states) => serde_json::from_slice::<HashMap<String, Vec<u8>>>(
                                        &states,
                                    ).stack_context(&log, "Error reading existing encrypted factor data")?,
                                    None => HashMap::new(),
                                };
                                for child in children {
                                    match state.entry(child.id.clone()) {
                                        Entry::Vacant(v) => {
                                            v.insert(local_encrypt(new_tokens.get(&child.id).unwrap(), &token));
                                        },
                                        Entry::Occupied(mut o) => {
                                            // Existing entry was encrypted with the child's old token
                                            if token_changed.contains(&child.id) {
                                                o.insert(local_encrypt(new_tokens.get(&child.id).unwrap(), &token));
                                            }
                                        },
                                    }
                                }
                                store_state.insert(new.id.clone(), serde_json::to_vec(&state).unwrap());
                                new_tokens.insert(new.id.clone(), token);
                            }
                        },
                        FactorTreeVariant::Password => {
                            let password: Vec<u8>;
                            if matches!(prev_variant, Some(FactorTreeVariant::Password)) {
                                // Same factor as before; carry the existing password forward rather than
                                // asking for a new one. First make sure it's been entered.
                                let Some(prev_token) = prev_tokens.get(&new.id) else {
                                    stack.push((Either::New(new.clone(), old.clone()), true));
                                    stack.push((Either::Prev(old.clone().unwrap()), true));
                                    continue;
                                };
                                match prev_scheme {
                                    TokenScheme::V2 => {
                                        // Token and stored salt remain valid
                                        new_tokens.insert(new.id.clone(), prev_token.clone());
                                        continue;
                                    },
                                    TokenScheme::Legacy => {
                                        // Legacy token is the raw password
                                        password = prev_token.clone();
                                    },
                                }
                            } else {
                                let Some(v) =
                                    ask(ui, Title::Initialize(new.desc.clone()), show_error.take(), Body::NewPassword {
                                        message: format!("Enter new password for [{}].", new.desc),
                                    }).await? else {
                                        return Ok(None);
                                    };
                                password = expect_bytes(v)?;
                            }
                            let (token, salt) = derive_entered_new(&password)?;
                            store_state.insert(new.id.clone(), salt);
                            new_tokens.insert(new.id.clone(), token);
                        },
                        FactorTreeVariant::Smartcards(c) => {
                            // Retrieve existing state data, or empty
                            let mut state = match prev_state.get(&new.id) {
                                Some(state) => serde_json::from_slice::<HashMap<String, Vec<u8>>>(
                                    &state,
                                ).stack_context(&log, "Error reading existing encrypted factor data")?,
                                None => HashMap::new(),
                            };

                            // Get token from old smartcards or generate a new one if there were none
                            let token = shed!{
                                'found _;
                                if let Some(key) = prev_tokens.get(&new.id) {
                                    break 'found key.clone();
                                }
                                if let Some(FactorTreeVariant::Smartcards(prev_children)) = prev_variant {
                                    let Some(token) =
                                        ui_unlock_smartcard(
                                            &log,
                                            ui,
                                            show_error.take(),
                                            Title::Initialize(new.desc.to_string()),
                                            prev_children,
                                            &state,
                                        ).await? else {
                                            return Ok(None);
                                        };
                                    break 'found token;
                                }
                                break 'found gen_token();
                            };

                            // Scan all new smartcards and generate new state data for them
                            let mut remaining_new_fingerprints = HashSet::new();
                            for child in &c.smartcards {
                                if state.contains_key(&child.fingerprint) {
                                    continue;
                                }
                                remaining_new_fingerprints.insert(child.fingerprint.clone());
                            }
                            let mut card_stream = CardStream::new(&log);
                            while !remaining_new_fingerprints.is_empty() {
                                let Some(mut card) =
                                    ui_get_smartcard(
                                        ui,
                                        &mut card_stream,
                                        show_error.take(),
                                        Title::Initialize(new.desc.to_string()),
                                        &remaining_new_fingerprints.iter().map(|x| x.as_str()).collect::<Vec<_>>(),
                                    ).await? else {
                                        return Ok(None);
                                    };
                                let mut card_tx = card.transaction().context("Error starting smartcard transaction")?;
                                let Some(pubkey) =
                                    card_tx
                                        .public_key(openpgp_card_sequoia::types::KeyType::Decryption)
                                        .map_err(|e| loga::err(e.to_string()))? else {
                                        show_error = Some("Couldn't determine public key for card.".to_string());
                                        continue;
                                    };
                                let fingerprint = pubkey.fingerprint().to_string();
                                if !remaining_new_fingerprints.remove(&fingerprint) {
                                    show_error =
                                        Some(format!("Smartcard had the wrong fingerprint: {}", fingerprint));
                                    continue;
                                };
                                let mut sink = vec![];
                                let message = Message::new(&mut sink);
                                let message =
                                    Encryptor2::for_recipients(message, vec![Recipient::from(&pubkey)])
                                        .build()
                                        .map_err(|e| loga::err(e.to_string()))
                                        .context("Error building encryptor")?;
                                let mut w =
                                    LiteralWriter::new(message)
                                        .build()
                                        .map_err(|e| loga::err(e.to_string()))
                                        .context("Error forming encryption writer")?;
                                w.write_all(&token).context("Error streaming data to encrypt")?;
                                w
                                    .finalize()
                                    .map_err(|e| loga::err(e.to_string()))
                                    .context("Error finalizing encryption")?;
                                state.insert(fingerprint.clone(), sink);
                            }

                            // Bundle + store everything
                            store_state.insert(new.id.clone(), serde_json::to_vec(&state).unwrap());
                            new_tokens.insert(new.id.clone(), token);
                        },
                        FactorTreeVariant::RecoveryPhrase => {
                            let phrase: Vec<u8>;
                            if matches!(prev_variant, Some(FactorTreeVariant::RecoveryPhrase)) {
                                // Same factor as before; keep the existing phrase valid. First make sure
                                // it's been entered.
                                let Some(prev_token) = prev_tokens.get(&new.id) else {
                                    stack.push((Either::New(new.clone(), old.clone()), true));
                                    stack.push((Either::Prev(old.clone().unwrap()), true));
                                    continue;
                                };
                                match prev_scheme {
                                    TokenScheme::V2 => {
                                        new_tokens.insert(new.id.clone(), prev_token.clone());
                                        continue;
                                    },
                                    TokenScheme::Legacy => {
                                        phrase = prev_token.clone();
                                    },
                                }
                            } else {
                                // Show
                                let words = generate::gen_bip39();
                                let Some(_) =
                                    ask(ui, Title::Initialize(new.desc.to_string()), show_error.take(), Body::ShowPhrase {
                                        message: "Write down this phrase list, with numbers, and store it somewhere secure."
                                            .to_string(),
                                        words: words.clone(),
                                    }).await? else {
                                        return Ok(None);
                                    };
                                let generated = words.join(" ").as_bytes().to_vec();

                                // Confirm
                                let Some(confirm_passphrase) =
                                    ui_recovery_entry(
                                        ui,
                                        show_error.take(),
                                        Title::Initialize(new.desc.to_string()),
                                        "Confirm the phrase.",
                                    ).await? else {
                                        return Ok(None);
                                    };
                                if confirm_passphrase != generated {
                                    return Err(
                                        UiErr::external(
                                            "Recovery phrases didn't match; make sure you wrote down the correct order as well.",
                                        ),
                                    );
                                }
                                phrase = generated;
                            }

                            // Save
                            let (token, salt) = derive_entered_new(&phrase)?;
                            store_state.insert(new.id.clone(), salt);
                            new_tokens.insert(new.id.clone(), token);
                        },
                    }
                }
            },
            Either::Prev(prev) => {
                let log = state.log.fork(ea!(factor = prev.id));
                if prev_tokens.contains_key(&prev.id) {
                    // nop
                } else {
                    match &prev.variant {
                        FactorTreeVariant::And(children) => {
                            if descending {
                                stack.push((at.clone(), false));
                                for child in children.iter().rev() {
                                    if prev_tokens.contains_key(&child.id) {
                                        continue;
                                    }
                                    stack.push((Either::Prev(child.clone()), true));
                                }
                            } else {
                                let token =
                                    and_token(
                                        prev_scheme,
                                        &children
                                            .iter()
                                            .map(|child| prev_tokens.get(&child.id).unwrap().as_slice())
                                            .collect::<Vec<_>>(),
                                    );
                                prev_tokens.insert(prev.id.clone(), token);
                            }
                        },
                        FactorTreeVariant::Or(children) => {
                            let state =
                                serde_json::from_slice::<HashMap<String, Vec<u8>>>(
                                    &prev_state
                                        .get(&prev.id)
                                        .context_with("State for factor missing in database", ea!(factor = prev.id))?,
                                ).context_with("Error parsing stored factor state", ea!(factor = prev.id))?;
                            let mut done = false;
                            for child in children {
                                if let Some(key) = prev_tokens.get(&child.id) {
                                    let token =
                                        match local_decrypt(
                                            &key,
                                            &state
                                                .get(&child.id)
                                                .context(&format!("Missing child state for [{}] in or", child.id))?,
                                        ).context("Error parsing stored state for factor")? {
                                            Some(t) => t,
                                            None => return Err(
                                                UiErr::External(
                                                    format!("Incorrect factor [{}], decryption failed", child.id),
                                                    None,
                                                ),
                                            ),
                                        };
                                    prev_tokens.insert(prev.id.clone(), token);
                                    done = true;
                                }
                            }
                            if !done {
                                stack.push((at.clone(), false));
                                let Some(child) =
                                    ui_choose(
                                        ui,
                                        show_error.take(),
                                        Title::Unlock(prev.desc.to_string()),
                                        children,
                                    ).await? else {
                                        return Ok(None);
                                    };
                                stack.push((Either::Prev(child), true));
                            }
                        },
                        FactorTreeVariant::Password => {
                            let Some(v) =
                                ask(ui, Title::Unlock(prev.desc.to_string()), show_error.take(), Body::Password {
                                    message: format!("Enter password for {}.", prev.desc),
                                }).await? else {
                                    return Ok(None);
                                };
                            let password = expect_bytes(v)?;
                            prev_tokens.insert(
                                prev.id.clone(),
                                derive_entered_prev(prev_scheme, &prev_state, &prev.id, password)?,
                            );
                        },
                        FactorTreeVariant::Smartcards(c) => {
                            let state =
                                serde_json::from_slice::<HashMap<String, Vec<u8>>>(
                                    &prev_state
                                        .get(&prev.id)
                                        .stack_context(&log, "Pretoken for factor missing in database")?,
                                ).stack_context(&log, "Unable to deserialize smartcards state")?;
                            let Some(token) =
                                ui_unlock_smartcard(
                                    &log,
                                    ui,
                                    show_error.take(),
                                    Title::Unlock(prev.desc.to_string()),
                                    c,
                                    &state,
                                ).await? else {
                                    return Ok(None);
                                };
                            prev_tokens.insert(prev.id.clone(), token);
                        },
                        FactorTreeVariant::RecoveryPhrase => {
                            let Some(phrase) =
                                ui_recovery_entry(
                                    ui,
                                    show_error.take(),
                                    Title::Unlock(prev.desc.to_string()),
                                    "Enter the recovery phrase words in the correct order.",
                                ).await? else {
                                    return Ok(None);
                                };
                            prev_tokens.insert(
                                prev.id.clone(),
                                derive_entered_prev(prev_scheme, &prev_state, &prev.id, phrase)?,
                            );
                        },
                    }
                }
            },
        }
    }
    return Ok(Some(DoCredsRes {
        prev_tokens: prev_tokens,
        new_tokens: new_tokens,
        store_state: store_state,
    }));
}

pub async fn do_initialize(
    state: Arc<FgState>,
    args: Arc<B2FInitialize>,
) -> Result<Option<B2FInitializeResult>, loga::Error> {
    let ui = UiClient::spawn(&state.log, &state.ui_config).await?;
    let ui = &ui;
    let Some(r) = ui_loop(&state.log.clone(), {
        let args = args.clone();
        let state = state.clone();
        move |show_err| do_creds(
            ui,
            state.clone(),
            args.tokens_changed.clone(),
            args.state_changed.clone(),
            args.prev_tokens.clone(),
            args.prev_state.clone(),
            show_err,
            args.prev_scheme,
            Either::New(args.root_factor.clone(), args.prev_root_factor.clone()),
        )
    }).await? else {
        return Ok(None);
    };
    return Ok(Some(B2FInitializeResult {
        root_token: r.new_tokens.get(&args.root_factor.id).map(|x| db_key(TokenScheme::V2, &x)),
        store_state: r.store_state,
    }));
}

pub async fn do_prompt(state: Arc<FgState>, args: Arc<B2FPrompt>) -> Result<Option<bool>, loga::Error> {
    let now = Instant::now();
    let mut elapsed_rule_desc = None;
    for (rule_id, (rule_desc, rule_remember)) in &args.prompt_rules {
        if let Some(last) = state.last_prompts.lock().unwrap().get(&rule_id) {
            if last.checked_add(Duration::from_secs(*rule_remember)).map(|x| x > now).unwrap_or(true) {
                continue;
            }
        }
        elapsed_rule_desc = Some(rule_desc.clone());
        break;
    }
    let Some(elapsed_rule_desc) = elapsed_rule_desc else {
        return Ok(Some(true));
    };
    let ui = UiClient::spawn(&state.log, &state.ui_config).await?;
    let ui = &ui;
    let out = ui_loop(&state.log, {
        let args = args.clone();
        move |_| {
            let elapsed_rule_desc = elapsed_rule_desc.clone();
            let args = args.clone();
            async move {
                let Some(v) = ask(ui, Title::Prompt(elapsed_rule_desc.clone()), None, Body::Prompt {
                    rule: elapsed_rule_desc,
                    principal: args.principal.clone(),
                    paths: args.paths.clone(),
                }).await? else {
                    return Ok(None);
                };
                return Ok(Some(expect_bool(v)?));
            }
        }
    }).await?;
    if out == Some(true) {
        for rule_id in args.prompt_rules.keys() {
            state.last_prompts.lock().unwrap().insert(*rule_id, now);
        }
    }
    return Ok(out);
}

pub async fn do_unlock(state: Arc<FgState>, args: Arc<B2FUnlock>) -> Result<Option<B2FUnlockResult>, loga::Error> {
    if args.require_exists && !args.privdb_path.exists() {
        // Otherwise sqlcipher would happily create a fresh empty database with
        // whatever was entered.
        return Err(
            loga::err_with(
                "Private database file is missing; refusing to unlock",
                ea!(path = args.privdb_path.to_string_lossy()),
            ),
        );
    }
    let ui = UiClient::spawn(&state.log, &state.ui_config).await?;
    let ui = &ui;
    return ui_loop(&state.log.clone(), move |show_err| {
        let args = args.clone();
        let state = state.clone();
        async move {
            let res =
                match do_creds(
                    ui,
                    state,
                    HashSet::new(),
                    HashSet::new(),
                    HashMap::new(),
                    args.state.clone(),
                    show_err,
                    args.scheme,
                    Either::Prev(args.root_factor.clone()),
                ).await? {
                    Some(x) => Arc::new(x),
                    None => return Ok(None),
                };
            let key = db_key(args.scheme, res.prev_tokens.get(&args.root_factor.id).unwrap());
            let privdbc = tokio::task::spawn_blocking({
                let args = args.clone();
                let key = key.clone();
                move || {
                    // Confirm token
                    let mut privdbc = open_privdb(&args.privdb_path, &key)?;
                    privdb::migrate(
                        &mut privdbc,
                    ).context_with("Error setting up priv database", ea!(path = args.privdb_path.to_string_lossy()))?;
                    return Ok(privdbc) as Result<_, loga::Error>;
                }
            })
                .await
                .map_err(|e| UiErr::InternalUnresolvable(loga::Error::from(e)))?
                .to_ui_err_external("Failed to unlock database")?;
            return Ok(Some(B2FUnlockResult {
                privdbc: privdbc,
                root_token: key,
                tokens: res.prev_tokens.clone(),
            }));
        }
    }).await;
}

struct DoCredsRes {
    new_tokens: HashMap<String, Vec<u8>>,
    prev_tokens: HashMap<String, Vec<u8>>,
    store_state: HashMap<String, Vec<u8>>,
}

#[derive(Clone)]
enum Either {
    /// New, optionally old - old is only used for unlocking via old creds when
    /// replacing stateful factors (namely or and smartcard which use stored encrypted
    /// generated keys).
    New(Arc<FactorTree>, Option<Arc<FactorTree>>),
    Prev(Arc<FactorTree>),
}

fn gen_token() -> Vec<u8> {
    let mut out = Vec::new();
    out.resize(32, 0u8);
    rng().fill_bytes(&mut out);
    return out;
}

/// Retry ui interaction as long as there are errors. `Ok(None)` aborts.
async fn ui_loop<
    T,
    F: Future<Output = Result<Option<T>, UiErr>>,
    N: FnMut(Option<String>) -> F,
>(log: &loga::Log, mut f: N) -> Result<Option<T>, loga::Error> {
    let mut show_error = None;
    loop {
        match f(show_error.take()).await {
            Ok(r) => return Ok(r),
            Err(e) => match e {
                UiErr::External(e, e_internal) => {
                    if let Some(e_internal) = e_internal {
                        log.log_err(loga::WARN, e_internal);
                    };
                    show_error = Some(e);
                },
                UiErr::Internal(e) => {
                    log.log_err(
                        loga::WARN,
                        e.context("An unexpected issue occurred while unlocking/initializing unlock credentials."),
                    );
                    show_error = Some("An unexpected error occurred, see log for details.".to_string());
                },
                UiErr::InternalUnresolvable(e) => {
                    return Err(e);
                },
            },
        }
    };
}

async fn ui_unlock_smartcard(
    log: &Log,
    ui: &UiClient,
    initial_warning: Option<String>,
    title: Title,
    config: &ConfigCredSmartcards,
    state: &HashMap<String, Vec<u8>>,
) -> Result<Option<Vec<u8>>, UiErr> {
    let mut card_stream = CardStream::new(&log);

    // Try various cards
    let mut warning = initial_warning;
    loop {
        match async {
            // Pin entry
            let pin = if !config.fixed_pin {
                let Some(v) = ask(ui, title.clone(), warning.take(), Body::Pin {
                    message: "Enter card PIN.".to_string(),
                }).await? else {
                    return Ok(None);
                };
                Some(expect_text(v)?)
            } else {
                None
            };
            let card =
                match ui_get_smartcard(
                    ui,
                    &mut card_stream,
                    warning.take(),
                    title.clone(),
                    &state.keys().map(|x: &String| x.as_str()).collect::<Vec<_>>(),
                ).await? {
                    Some(c) => c,
                    None => {
                        return Ok(None);
                    },
                };
            let (card, pubkey) = get_card_pubkey(card).await?;
            let Some(card_config) =
                config.smartcards.iter().filter(|c| c.fingerprint == pubkey.fingerprint().to_string()).next() else {
                    return Ok(None);
                };
            // Only use the configured pin in fixed-pin mode; otherwise the user was just
            // asked for one and that's what should be sent to the card.
            let card = card.enter_pin(if config.fixed_pin {
                card_config.pin.clone()
            } else {
                pin
            }).await?;
            match card
                .decrypt(
                    state
                        .get(&card_config.fingerprint)
                        .context_with(
                            "Missing stored state for smartcard with fingerprint",
                            ea!(fingerprint = card_config.fingerprint),
                        )?
                        .clone(),
                )
                .await? {
                crypto::MaybeNeedTouch::NeedTouch(card) => {
                    let mut w = ui.open(title.clone(), warning.take(), Body::Message {
                        message: format!("Confirm the action on the smartcard {}", card_config.fingerprint),
                    });
                    select!{
                        r = w.wait() => {
                            r.map_err(|e| UiErr::InternalUnresolvable(e))?;
                            return Ok(None);
                        },
                        r = card.wait_for_touch() => {
                            let (_, decrypted) = r?;
                            return Ok(Some(decrypted));
                        },
                    }
                },
                crypto::MaybeNeedTouch::Decryptor(_, decrypted) => {
                    return Ok(Some(decrypted));
                },
            }
        }.await {
            Ok(r) => return Ok(r),
            Err(e) => match e {
                UiErr::Internal(i) => {
                    log.log_err(loga::WARN, i);
                    warning = Some("Internal error, check logs for details.".to_string());
                    continue;
                },
                UiErr::External(e, i) => {
                    if let Some(i) = i {
                        log.log_err(loga::WARN, i);
                    }
                    warning = Some(e);
                    continue;
                },
                UiErr::InternalUnresolvable(e) => {
                    return Err(UiErr::InternalUnresolvable(e));
                },
            },
        }
    }
}
