use std::{
    cell::RefCell,
    collections::{
        hash_map::Entry,
        HashMap,
        HashSet,
    },
    future::Future,
    io::Write,
    path::PathBuf,
    rc::Rc,
    sync::{
        Arc,
    },
    time::{
        Duration,
        Instant,
    },
};
use loga::{
    ea,
    ResultContext,
    StandardFlag,
    StandardLog,
};
use openpgp_card_sequoia::{
    state::Open,
};
use passworth::{
    bb,
    config::{
        ConfigCredSmartcard,
        ConfigCredSmartcardPin,
    },
    crypto::{
        self,
        get_card_pubkey,
        local_decrypt,
        local_encrypt,
        CardStream,
    },
    error::{
        FromAnyErr,
        ToUiErr,
        UiErr,
    },
    generate::{
        self,
        BIP39,
        BIP39_PHRASELEN,
    },
};
use rand::{
    thread_rng,
    RngCore,
};
use rusqlite::Connection;
use sequoia_openpgp::serialize::stream::{
    Encryptor2,
    LiteralWriter,
    Message,
    Recipient,
};
use tokio::{
    sync::{
        mpsc,
        oneshot,
    },
};
use crate::{
    open_privdb,
    FactorTree,
    FactorTreeVariant,
};
use super::{
    privdb,
};
use gtk4::{
    gio::ApplicationFlags,
    prelude::{
        ApplicationExt,
        ApplicationExtManual,
        BoxExt,
        ButtonExt,
        EditableExt,
        EditableExtManual,
        GridExt,
        GtkWindowExt,
        RangeExt,
        WidgetExt,
    },
    Application,
};

pub struct FgState {
    pub log: StandardLog,
    pub last_prompts: HashMap<usize, Instant>,
}

async fn form_dialog<
    T: 'static,
>(
    app: &Application,
    title: &str,
    initial_warning: Option<String>,
    body: &impl gtk4::glib::object::IsA<gtk4::Widget>,
    f: impl Fn() -> Result<T, String> + 'static,
) -> Option<T> {
    let (res_tx, res_rx) = oneshot::channel();
    let window = Rc::new(gtk4::ApplicationWindow::builder().application(app).title(title).build());
    let layout = vbox();
    let warning = {
        let w = gtk4::Label::builder().build();
        if let Some(text) = initial_warning {
            w.set_label(&text);
        } else {
            w.set_visible(false);
        }
        layout.append(&w);
        w
    };
    layout.append(body);
    layout.append(&{
        let submit = gtk4::Button::builder().icon_name("ok").label("Ok").halign(gtk4::Align::End).build();
        submit.connect_clicked({
            let window = window.clone();
            let res_tx = RefCell::new(Some(res_tx));
            move |_button| {
                match f() {
                    Ok(r) => {
                        _ = res_tx.borrow_mut().take().unwrap().send(r);
                        window.close();
                    },
                    Err(e) => {
                        warning.set_label(&e);
                        warning.set_visible(true);
                    },
                }
            }
        });
        submit
    });
    window.set_child(Some(&layout));
    window.present();
    return res_rx.await.ok();
}

fn gen_token() -> Vec<u8> {
    let mut out = Vec::new();
    out.resize(32, 0u8);
    thread_rng().fill_bytes(&mut out);
    return out;
}

async fn ui_choose(
    app: &Application,
    initial_warning: Option<String>,
    choices: &Vec<Arc<FactorTree>>,
) -> Option<Arc<FactorTree>> {
    let (res_tx, mut res_rx) = mpsc::channel(1);
    let window =
        Rc::new(
            gtk4::ApplicationWindow::builder().application(app).title("Passworth - Choose unlock method").build(),
        );
    let layout = vbox();
    if let Some(warning) = initial_warning {
        layout.append(&gtk4::Label::builder().label(warning).build());
    }
    layout.append(&gtk4::Label::builder().label("Choose an unlock method.").build());
    for method in choices {
        let button = gtk4::Button::builder().label(&method.desc).build();
        button.connect_clicked({
            let window = window.clone();
            let method = method.clone();
            let res_tx = res_tx.clone();
            move |_| {
                _ = res_tx.send(method.clone());
                window.close();
            }
        });
        layout.append(&button);
    }
    window.set_child(Some(&layout));
    window.present();
    return res_rx.recv().await;
}

async fn ui_get_smartcard(
    app: &Application,
    card_stream: &mut CardStream,
    title: &str,
    initial_warning: Option<String>,
) -> Option<openpgp_card_sequoia::Card<Open>> {
    let window =
        Rc::new(
            gtk4::ApplicationWindow::builder().application(app).title("Passworth - Choose unlock method").build(),
        );
    let layout = vbox();
    if let Some(warning) = initial_warning {
        layout.append(&gtk4::Label::builder().label(warning).build());
    }
    layout.append(
        &gtk4::Label::builder().label(&format!("Insert or swipe smartcard with GPG fingerprint: {}", title)).build(),
    );
    window.set_child(Some(&layout));
    window.present();
    defer::defer({
        let window = window.clone();
        move || {
            window.close();
        }
    });
    return card_stream.next().await;
}

async fn ui_unlock_smartcard(
    log: &StandardLog,
    app: &Application,
    initial_warning: Option<String>,
    configs: &Vec<ConfigCredSmartcard>,
    state: &HashMap<String, Vec<u8>>,
) -> Result<Option<Vec<u8>>, UiErr> {
    let mut card_stream = CardStream::new(&log);

    // Try various cards
    let mut warning = initial_warning;
    loop {
        match async {
            let card =
                match ui_get_smartcard(
                    app,
                    &mut card_stream,
                    &state.keys().map(|x: &String| x.as_str()).collect::<Vec<_>>().join(", "),
                    warning.take(),
                ).await {
                    Some(c) => c,
                    None => {
                        return Ok(None);
                    },
                };
            let (card, pubkey) = get_card_pubkey(card).await?;
            let Some(config) = configs.iter().filter(|c| c.fingerprint == pubkey.keyid().to_string()).next() else {
                return Ok(None);
            };

            // Pin entry
            let pin = match &config.pin {
                ConfigCredSmartcardPin::Hardcode(pin) => {
                    Some(pin.clone())
                },
                ConfigCredSmartcardPin::None => {
                    None
                },
                ConfigCredSmartcardPin::Prompt => {
                    let digits = Rc::new(RefCell::new(vec![]));
                    let layout = vbox();
                    if let Some(warning) = warning.take() {
                        layout.append(&gtk4::Label::builder().label(warning).build());
                    }
                    layout.append(&gtk4::Label::builder().label("Enter card PIN").build());
                    let pin_layout = gtk4::Grid::builder().build();
                    for i in 1 ..= 9 {
                        let row = i % 3;
                        let column = i / 3;
                        let button = gtk4::Button::builder().label(i.to_string()).build();
                        button.connect_clicked({
                            let digits = digits.clone();
                            move |_button| {
                                digits.borrow_mut().push(i.to_string());
                            }
                        });
                        pin_layout.attach(&button, 3 - row, column, 1, 1);
                    }
                    {
                        let button = gtk4::Button::builder().label("0").build();
                        button.connect_clicked({
                            let digits = digits.clone();
                            move |_button| {
                                digits.borrow_mut().push(0.to_string());
                            }
                        });
                        pin_layout.attach(&button, 0, 4, 1, 1);
                    }
                    {
                        let button = gtk4::Button::builder().icon_name("clear").build();
                        button.connect_clicked({
                            let digits = digits.clone();
                            move |_button| {
                                digits.borrow_mut().clear();
                            }
                        });
                        pin_layout.attach(&button, 1, 4, 1, 1);
                    }
                    layout.append(&pin_layout);
                    let pin = match form_dialog(&app, "Passworth - Unlock PIN entry", warning.take(), &layout, {
                        let digits = digits.clone();
                        move || {
                            return Ok(digits.borrow_mut().join(""));
                        }
                    }).await {
                        Some(x) => x,
                        None => {
                            return Ok(None);
                        },
                    };
                    Some(pin)
                },
            };
            let card = card.enter_pin(pin).await?;
            match card
                .decrypt(
                    state
                        .get(&config.fingerprint)
                        .context_with(
                            "Missing stored state for smartcard with fingerprint",
                            ea!(fingerprint = config.fingerprint),
                        )?
                        .clone(),
                )
                .await? {
                crypto::MaybeNeedTouch::NeedTouch(card) => {
                    let window =
                        Rc::new(
                            gtk4::ApplicationWindow::builder()
                                .application(app)
                                .title("Passworth - Smartcard requires interaction")
                                .build(),
                        );
                    let layout = vbox();
                    if let Some(warning) = warning.take() {
                        layout.append(&gtk4::Label::builder().label(warning).build());
                    }
                    layout.append(
                        &gtk4::Label::builder()
                            .label(&format!("Confirm the action on the smartcard {}", config.fingerprint))
                            .build(),
                    );
                    window.set_child(Some(&layout));
                    window.present();
                    defer::defer({
                        let window = window.clone();
                        move || {
                            window.close();
                        }
                    });
                    let (_, decrypted) = card.wait_for_touch().await?;
                    return Ok(Some(decrypted));
                },
                crypto::MaybeNeedTouch::Decryptor(_, decrypted) => {
                    return Ok(Some(decrypted));
                },
            }
        }.await {
            Ok(r) => return Ok(r),
            Err(e) => match e {
                UiErr::Internal(i) => {
                    log.log_err(StandardFlag::Warning, i);
                    warning = Some("Internal error, check logs for details.".to_string());
                    continue;
                },
                UiErr::External(e, i) => {
                    if let Some(i) = i {
                        log.log_err(StandardFlag::Warning, i);
                    }
                    warning = Some(e);
                    continue;
                },
            },
        }
    }
}

#[derive(Clone)]
enum Either {
    /// New, optionally old - old is only used for unlocking via old creds when
    /// replacing stateful factors (namely or and smartcard which use stored encrypted
    /// generated keys).
    New(Arc<FactorTree>, Option<Arc<FactorTree>>),
    Prev(Arc<FactorTree>),
}

fn vbox() -> gtk4::Box {
    return gtk4::Box::new(gtk4::Orientation::Vertical, 4);
}

fn hbox() -> gtk4::Box {
    return gtk4::Box::new(gtk4::Orientation::Horizontal, 4);
}

struct DoCredsRes {
    prev_tokens: HashMap<String, Vec<u8>>,
    new_tokens: HashMap<String, Vec<u8>>,
    store_state: HashMap<String, Vec<u8>>,
}

fn ui<
    T: 'static,
    F: Future<Output = Result<Option<T>, UiErr>>,
    N: 'static + FnMut(Application, Option<String>) -> F,
>(log: &loga::StandardLog, f: N) -> Option<T> {
    let res = Rc::new(RefCell::new(None));
    let app = gtk4::Application::builder().application_id("x.passworth").flags(ApplicationFlags::FLAGS_NONE).build();
    let log = log.clone();
    let f = Rc::new(RefCell::new(Some(f)));
    app.connect_activate({
        let res = res.clone();
        move |app| {
            let app = app.clone();
            let res = res.clone();
            let log = log.clone();
            let mut f = f.borrow_mut().take().unwrap();
            gtk4::glib::spawn_future_local(async move {
                let _close = defer::defer({
                    let app = app.clone();
                    move || {
                        app.quit();
                    }
                });
                let mut show_error = None;
                *res.borrow_mut() = loop {
                    match f(app.clone(), show_error.take()).await {
                        Ok(r) => break r,
                        Err(e) => match e {
                            UiErr::External(e, e_internal) => {
                                if let Some(e_internal) = e_internal {
                                    log.log_err(StandardFlag::Warning, e_internal);
                                };
                                show_error = Some(e);
                            },
                            UiErr::Internal(e) => {
                                log.log_err(
                                    StandardFlag::Warning,
                                    e.context(
                                        "An unexpected issue occurred while unlocking/initializing unlock credentials.",
                                    ),
                                );
                                show_error = Some("An unexpected error occurred, see log for details.".to_string());
                            },
                        },
                    }
                };
            });
        }
    });
    app.run_with_args(&[] as &[String]);
    return res.borrow_mut().take();
}

async fn do_creds(
    app: Application,
    token_changed: HashSet<String>,
    state_changed: HashSet<String>,
    mut prev_tokens: HashMap<String, Vec<u8>>,
    prev_state: HashMap<String, Vec<u8>>,
    mut show_error: Option<String>,
    start: Either,
) -> Result<Option<DoCredsRes>, UiErr> {
    // Results:
    //
    // * Error - retry
    //
    // * Close window (None) - exit with error
    //
    // * Success
    let mut stack = vec![(start, true)];
    let mut new_tokens = HashMap::<String, Vec<u8>>::new();
    let mut store_state = HashMap::<String, Vec<u8>>::new();
    while let Some((at, descending)) = stack.pop() {
        match &at {
            Either::New(new, old) => {
                let log = StandardLog::new().fork(ea!(factor = new.id));
                let prev_variant = old.as_ref().map(|x| &x.variant);
                if new_tokens.contains_key(&new.id) {
                    // nop
                } else if Some(new) == old.as_ref() {
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
                                let mut token = vec![];
                                for child in children {
                                    token.extend(new_tokens.get(&child.id).unwrap());
                                }
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
                                        let Some(
                                            child
                                        ) = ui_choose(&app, show_error.take(), &prev_children).await else {
                                            return Ok(None);
                                        };
                                        stack.push((Either::Prev(child), true));
                                    }
                                }
                            } else {
                                // Get or token
                                let token = bb!{
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
                                    let Entry:: Vacant(v) = state.entry(child.id.clone()) else {
                                        continue;
                                    };
                                    v.insert(local_encrypt(&token, new_tokens.get(&child.id).unwrap()));
                                }
                                store_state.insert(new.id.clone(), serde_json::to_vec(&state).unwrap());
                                new_tokens.insert(new.id.clone(), token);
                            }
                        },
                        FactorTreeVariant::Password => {
                            let layout = vbox();
                            if let Some(warning) = show_error.take() {
                                layout.append(&gtk4::Label::builder().label(warning).build());
                            }
                            layout.append(
                                &gtk4::Label::builder()
                                    .label(&format!("Enter new password for {}.", new.desc))
                                    .build(),
                            );
                            if let Some(warning) = show_error.take() {
                                layout.append(
                                    &gtk4::Label::builder().label(&format!("Error: {}", warning)).build(),
                                );
                            }
                            let generators =
                                [
                                    ("Alphanumeric", generate::gen_alphanum as fn(usize) -> String),
                                    ("Lowercase alphanumeric", generate::gen_safe_alphanum),
                                    ("Alphanumeric and symbols", generate::gen_alphanum_symbols),
                                ];
                            let generate_dropdown = gtk4::DropDown::builder().build();
                            let generate_len = gtk4::Scale::builder().build();
                            let generate_button = gtk4::Button::builder().label("Generate").build();
                            {
                                let generate_layout = vbox();
                                let line1 = hbox();
                                let dropdown_strings = gtk4::StringList::new(&[]);
                                for (title, _) in generators {
                                    dropdown_strings.append(&title);
                                }
                                line1.append(&generate_dropdown);
                                line1.append(&generate_button);
                                let line2 = hbox();
                                line2.append(&gtk4::Label::builder().label("Length").build());
                                generate_len.set_round_digits(0);
                                generate_len.set_range(5., 50.);
                                generate_len.set_value(16.);
                                line2.append(&generate_len);
                                let expander = gtk4::Expander::builder().label("Generate").build();
                                expander.set_child(Some(&generate_layout));
                                layout.append(&expander);
                            }
                            let form_layout = gtk4::Grid::builder().build();
                            form_layout.attach(
                                &gtk4::Label::builder().label("Password").halign(gtk4::Align::End).build(),
                                1,
                                1,
                                1,
                                1,
                            );
                            let password = {
                                let password = gtk4::PasswordEntry::builder().build();
                                form_layout.attach(&password, 2, 1, 1, 1);
                                password
                            };
                            form_layout.attach(
                                &gtk4::Label::builder().label("Confirm").halign(gtk4::Align::End).build(),
                                1,
                                2,
                                1,
                                1,
                            );
                            let confirm_password = {
                                let confirm_password = gtk4::PasswordEntry::builder().build();
                                form_layout.attach(&confirm_password, 2, 2, 1, 1);
                                confirm_password
                            };
                            layout.append(&form_layout);
                            generate_button.connect_clicked({
                                let dropdown = generate_dropdown.clone();
                                let password = password.clone();
                                let confirm_password = confirm_password.clone();
                                move |_button| {
                                    confirm_password.set_text("");
                                    password.set_text(
                                        &(generators[dropdown.selected() as usize].1)(generate_len.value() as usize),
                                    );
                                }
                            });
                            let Some(
                                password
                            ) = form_dialog(&app, "Passworth - New unlock password", show_error.take(), &layout, {
                                move || {
                                    if password.text() == confirm_password.text() {
                                        return Ok(password.text().as_bytes().to_vec());
                                    } else {
                                        return Err("Password mismatch".to_string());
                                    }
                                }
                            }).await else {
                                return Ok(None);
                            };
                            new_tokens.insert(new.id.clone(), password);
                        },
                        FactorTreeVariant::Smartcard(c) => {
                            // Retrieve existing state data, or empty
                            let mut state = match prev_state.get(&new.id) {
                                Some(state) => serde_json::from_slice::<HashMap<String, Vec<u8>>>(
                                    &state,
                                ).stack_context(&log, "Error reading existing encrypted factor data")?,
                                None => HashMap::new(),
                            };

                            // Get token from old smartcards or generate a new one if there were none
                            let token = bb!{
                                'found _;
                                if let Some(key) = prev_tokens.get(&new.id) {
                                    break 'found key.clone();
                                }
                                if let Some(FactorTreeVariant::Smartcard(prev_children)) = prev_variant {
                                    let Some(
                                        token
                                    ) = ui_unlock_smartcard(
                                        &log,
                                        &app,
                                        show_error.take(),
                                        prev_children,
                                        &state
                                    ).await ? else {
                                        return Ok(None);
                                    };
                                    break 'found token;
                                }
                                break 'found gen_token();
                            };

                            // Scan all new smartcards and generate new state data for them
                            let mut remaining_new_fingerprints = HashSet::new();
                            for child in c {
                                if state.contains_key(&child.fingerprint) {
                                    continue;
                                }
                                remaining_new_fingerprints.insert(child.fingerprint.clone());
                            }
                            let mut card_stream = CardStream::new(&log);
                            while !remaining_new_fingerprints.is_empty() {
                                let Some(
                                    mut card
                                ) = ui_get_smartcard(
                                    &app,
                                    &mut card_stream,
                                    &format!(
                                        "Insert or tap one of the following new smartcards: {}",
                                        remaining_new_fingerprints.iter().cloned().collect::<Vec<_>>().join(", ")
                                    ),
                                    show_error.take()
                                ).await else {
                                    return Ok(None);
                                };
                                let mut card_tx = card.transaction().context("Error starting smartcard transaction")?;
                                let Some(
                                    pubkey
                                ) = card_tx.public_key(
                                    openpgp_card_sequoia::types::KeyType::Decryption
                                ).map_err(|e| loga::err(e.to_string())) ? else {
                                    show_error = Some("Couldn't determine public key for card.".to_string());
                                    continue;
                                };
                                let fingerprint = pubkey.keyid().to_string();
                                remaining_new_fingerprints.remove(&fingerprint);
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
                            let layout = vbox();
                            if let Some(warning) = show_error.take() {
                                layout.append(&gtk4::Label::builder().label(warning).build());
                            }
                            layout.append(
                                &gtk4::Label::builder()
                                    .label("Write down this phrase list, with numbers, and store it somewhere secure.")
                                    .build(),
                            );
                            let form_layout = gtk4::Grid::builder().build();
                            let phrase = generate::gen_bip39();
                            for (i, word) in phrase.iter().enumerate() {
                                form_layout.attach(
                                    &gtk4::Label::builder()
                                        .label(&format!("{}. {}", i + 1, word))
                                        .halign(gtk4::Align::Start)
                                        .build(),
                                    1 + i as i32 / (BIP39_PHRASELEN as i32 / 2),
                                    1 + i as i32 % (BIP39_PHRASELEN as i32 / 2),
                                    1,
                                    1,
                                );
                            }
                            layout.append(&form_layout);
                            form_dialog(&app, "Passworth - New recovery phrase", show_error.take(), &layout, || {
                                return Ok(());
                            }).await.stack_context(&log, "Error dialog closed")?;
                            new_tokens.insert(new.id.clone(), phrase.join(" ").as_bytes().to_vec());
                        },
                    }
                }
            },
            Either::Prev(prev) => {
                let log = StandardLog::new().fork(ea!(factor = prev.id));
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
                                let mut token = vec![];
                                for child in children {
                                    token.extend(prev_tokens.get(&child.id).unwrap());
                                }
                                prev_tokens.insert(prev.id.clone(), token);
                            }
                        },
                        FactorTreeVariant::Or(children) => {
                            let state =
                                prev_state
                                    .get(&prev.id)
                                    .stack_context(&log, "Pretoken for factor missing in database")?;
                            let mut done = false;
                            for child in children {
                                if let Some(child_token1) = prev_tokens.get(&child.id) {
                                    let token =
                                        match local_decrypt(
                                            &child_token1,
                                            state,
                                        ).stack_context(&log, "Error parsing stored state")? {
                                            Some(t) => t,
                                            None => return Err(UiErr::external("Incorrect factor")),
                                        };
                                    prev_tokens.insert(prev.id.clone(), token);
                                    done = true;
                                }
                            }
                            if !done {
                                stack.push((at.clone(), false));
                                let Some(child) = ui_choose(&app, show_error.take(), children).await else {
                                    return Ok(None);
                                };
                                stack.push((Either::Prev(child), true));
                            }
                        },
                        FactorTreeVariant::Password => {
                            let layout = vbox();
                            if let Some(warning) = show_error.take() {
                                layout.append(&gtk4::Label::builder().label(warning).build());
                            }
                            layout.append(
                                &gtk4::Label::builder().label(&format!("Enter password for {}.", prev.desc)).build(),
                            );
                            if let Some(warning) = show_error.take() {
                                layout.append(
                                    &gtk4::Label::builder().label(&format!("Error: {}", warning)).build(),
                                );
                            }
                            let form_layout = gtk4::Grid::builder().build();
                            form_layout.attach(
                                &gtk4::Label::builder().label("Password").halign(gtk4::Align::End).build(),
                                1,
                                1,
                                1,
                                1,
                            );
                            let password = {
                                let password = Rc::new(gtk4::PasswordEntry::builder().build());
                                form_layout.attach(password.as_ref(), 2, 1, 1, 1);
                                password
                            };
                            layout.append(&form_layout);
                            let Some(password) = form_dialog(&app, "Passworth - Unlock", show_error.take(), &layout, {
                                move || {
                                    return Ok(password.text().as_bytes().to_vec());
                                }
                            }).await else {
                                return Ok(None);
                            };
                            prev_tokens.insert(prev.id.clone(), password);
                        },
                        FactorTreeVariant::Smartcard(c) => {
                            let state =
                                serde_json::from_slice::<HashMap<String, Vec<u8>>>(
                                    &prev_state
                                        .get(&prev.id)
                                        .stack_context(&log, "Pretoken for factor missing in database")?,
                                ).stack_context(&log, "Unable to deserialize smartcards state")?;
                            let Some(
                                token
                            ) = ui_unlock_smartcard(&log, &app, show_error.take(), c, &state).await ? else {
                                return Ok(None);
                            };
                            prev_tokens.insert(prev.id.clone(), token);
                        },
                        FactorTreeVariant::RecoveryPhrase => {
                            let layout = vbox();
                            if let Some(warning) = show_error.take() {
                                layout.append(&gtk4::Label::builder().label(warning).build());
                            }
                            layout.append(
                                &gtk4::Label::builder()
                                    .label("Write down this phrase list, with numbers, and store it somewhere secure.")
                                    .build(),
                            );
                            let word_set = Rc::new(BIP39.iter().map(|x| *x).collect::<HashSet<_>>());
                            let form_layout = gtk4::Grid::builder().build();
                            let mut entries = vec![];
                            for i in 0 .. BIP39_PHRASELEN {
                                let col = 1 + (i as i32 / (BIP39_PHRASELEN as i32 / 2)) * 2;
                                let row = 1 + i as i32 % (BIP39_PHRASELEN as i32 / 2);
                                form_layout.attach(
                                    &gtk4::Label::builder()
                                        .label(&format!("{}.", i + 1))
                                        .halign(gtk4::Align::End)
                                        .build(),
                                    col,
                                    row,
                                    1,
                                    1,
                                );
                                let entry = gtk4::Entry::builder().build();
                                entry.connect_insert_text({
                                    let word_set = word_set.clone();
                                    move |entry, text, _| {
                                        if word_set.contains(text) {
                                            entry.add_css_class("error");
                                        } else {
                                            entry.remove_css_class("error");
                                        }
                                    }
                                });
                                form_layout.attach(&entry, col + 1, row, 1, 1);
                                entries.push(entry);
                            }
                            layout.append(&form_layout);
                            let phrase =
                                form_dialog(
                                    &app,
                                    "Passworth - New recovery phrase",
                                    show_error.take(),
                                    &layout,
                                    move || {
                                        for entry in &entries {
                                            if !word_set.contains(entry.text().as_str()) {
                                                return Err("Some words are spelled incorrectly".to_string());
                                            }
                                        }
                                        return Ok(
                                            entries
                                                .iter()
                                                .map(|x| x.text().to_string())
                                                .collect::<Vec<_>>()
                                                .join(" ")
                                                .as_bytes()
                                                .to_vec(),
                                        );
                                    },
                                ).await.stack_context(&log, "Error dialog closed")?;
                            prev_tokens.insert(prev.id.clone(), phrase);
                        },
                    }
                }
            },
        }
    }
    return Ok(Some(DoCredsRes {
        prev_tokens: prev_tokens,
        new_tokens: new_tokens,
        store_state,
    }));
}

pub struct B2FUnlock {
    pub privdb_path: PathBuf,
    pub root_factor: Arc<FactorTree>,
    pub state: HashMap<String, Vec<u8>>,
}

pub struct B2FUnlockResult {
    pub privdbc: Connection,
    pub root_token: String,
    pub tokens: HashMap<String, Vec<u8>>,
}

pub fn do_unlock(log: &loga::StandardLog, args: Arc<B2FUnlock>) -> Option<B2FUnlockResult> {
    return ui(log, move |app, show_err| {
        let args = args.clone();
        async move {
            let res =
                match do_creds(
                    app,
                    HashSet::new(),
                    HashSet::new(),
                    HashMap::new(),
                    args.state.clone(),
                    show_err,
                    Either::Prev(args.root_factor.clone()),
                ).await? {
                    Some(x) => Arc::new(x),
                    None => return Ok(None),
                };
            let privdbc = gtk4::gio::spawn_blocking({
                let args = args.clone();
                let res = res.clone();
                move || {
                    // Confirm token
                    let mut privdbc =
                        open_privdb(
                            &args.privdb_path,
                            &zbase32::encode_full_bytes(&res.prev_tokens.get(&args.root_factor.id).unwrap()),
                        )?;
                    privdb::migrate(
                        &mut privdbc,
                    ).context_with("Error setting up priv database", ea!(path = args.privdb_path.to_string_lossy()))?;
                    return Ok(privdbc) as Result<_, loga::Error>;
                }
            }).await.any_context()?.to_ui_err_external("Failed to unlock database")?;
            return Ok(Some(B2FUnlockResult {
                privdbc: privdbc,
                root_token: zbase32::encode_full_bytes(&res.prev_tokens.get(&args.root_factor.id).unwrap().clone()),
                tokens: res.prev_tokens.clone(),
            }));
        }
    });
}

pub struct B2FInitialize {
    pub privdbc: Option<Connection>,
    pub root_factor: Arc<FactorTree>,
    pub tokens_changed: HashSet<String>,
    pub state_changed: HashSet<String>,
    pub prev_tokens: HashMap<String, Vec<u8>>,
    pub prev_root_factor: Option<Arc<FactorTree>>,
    pub prev_state: HashMap<String, Vec<u8>>,
}

pub struct B2FInitializeResult {
    pub root_token: Option<String>,
    pub store_state: HashMap<String, Vec<u8>>,
}

pub fn do_initialize(log: &loga::StandardLog, args: Arc<B2FInitialize>) -> Option<B2FInitializeResult> {
    let Some(r) = ui(log, {
        let args = args.clone();
        move |app, show_err| do_creds(
            app,
            args.tokens_changed.clone(),
            args.state_changed.clone(),
            args.prev_tokens.clone(),
            args.prev_state.clone(),
            show_err,
            Either::New(args.root_factor.clone(), args.prev_root_factor.clone()),
        )
    }) else {
        return None;
    };
    return Some(B2FInitializeResult {
        root_token: r.new_tokens.get(&args.root_factor.id).map(|x| zbase32::encode_full_bytes(&x)),
        store_state: r.store_state,
    });
}

pub struct B2FPrompt {
    pub prompt_rules: HashMap<usize, (String, u64)>,
}

pub fn do_prompt(state: &mut FgState, args: Arc<B2FPrompt>) -> Option<bool> {
    let now = Instant::now();
    let mut elapsed_rule_desc = None;
    for (rule_id, (rule_desc, rule_remember)) in &args.prompt_rules {
        if let Some(last) = state.last_prompts.get(&rule_id) {
            if last.checked_add(Duration::from_secs(*rule_remember)).map(|x| x > now).unwrap_or(true) {
                continue;
            }
        }
        elapsed_rule_desc = Some(rule_desc.clone());
        break;
    }
    let Some(elapsed_rule_desc) = elapsed_rule_desc else {
        return Some(true);
    };
    let out = ui(&state.log, move |app, _| {
        let elapsed_rule_desc = elapsed_rule_desc.clone();
        async move {
            let (res_tx, res_rx) = oneshot::channel();
            let res_tx = Rc::new(RefCell::new(Some(res_tx)));
            let window =
                Rc::new(gtk4::ApplicationWindow::builder().application(&app).title("Passworth - Confirm").build());
            let layout = vbox();
            layout.append(&gtk4::Label::builder().label(&elapsed_rule_desc).build());
            let button_layout = hbox();
            button_layout.append(&{
                let submit =
                    gtk4::Button::builder().icon_name("cancel").label("Cancel").halign(gtk4::Align::End).build();
                submit.connect_clicked({
                    let window = window.clone();
                    let res_tx = res_tx.clone();
                    move |_button| {
                        _ = res_tx.borrow_mut().take().unwrap().send(false);
                        window.close();
                    }
                });
                submit
            });
            button_layout.append(&{
                let submit = gtk4::Button::builder().icon_name("ok").label("Ok").halign(gtk4::Align::End).build();
                submit.connect_clicked({
                    let window = window.clone();
                    let res_tx = res_tx.clone();
                    move |_button| {
                        _ = res_tx.borrow_mut().take().unwrap().send(true);
                        window.close();
                    }
                });
                submit
            });
            window.set_child(Some(&layout));
            window.present();
            return Ok(res_rx.await.ok());
        }
    });
    if out == Some(true) {
        for rule_id in args.prompt_rules.keys() {
            state.last_prompts.insert(*rule_id, now);
        }
    }
    return out;
}

pub enum B2F {
    Initialize(B2FInitialize, oneshot::Sender<B2FInitializeResult>),
    Unlock(B2FUnlock, oneshot::Sender<B2FUnlockResult>),
    Prompt(B2FPrompt, oneshot::Sender<bool>),
}
