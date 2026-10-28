use {
    card_backend_pcsc::PcscBackend,
    chacha20poly1305::{
        AeadCore,
        ChaCha20Poly1305,
        KeyInit,
        aead::Aead,
    },
    flowcontrol::shed,
    loga::{
        ErrContext,
        ResultContext,
    },
    openpgp_card_sequoia::{
        PublicKey,
        state::Open,
    },
    sequoia_openpgp::{
        parse::{
            Parse,
            stream::DecryptorBuilder,
        },
        policy::StandardPolicy,
    },
    serde::{
        Deserialize,
        Serialize,
    },
    sha2::{
        Digest,
        Sha256,
    },
    std::{
        collections::HashSet,
        io::Cursor,
        sync::{
            Arc,
            atomic::{
                AtomicBool,
                Ordering,
            },
        },
        thread::sleep,
        time::Duration,
    },
    super::error::{
        ToUiErr,
        UiErr,
    },
    tokio::{
        runtime,
        select,
        sync::{
            mpsc::{
                channel,
                self,
            },
            oneshot,
        },
    },
};

pub struct CardStream {
    alive: Arc<AtomicBool>,
    rx: mpsc::Receiver<openpgp_card_sequoia::Card<Open>>,
}

impl CardStream {
    pub fn new(log: &loga::Log) -> Self {
        let alive = Arc::new(AtomicBool::new(true));
        let (stream_tx, stream_rx) = channel(100);
        let log = log.clone();
        std::thread::spawn({
            let alive = alive.clone();
            move || {
                let stream_tx = stream_tx;
                let mut loop_state = None;
                let mut watch: Vec<pcsc::ReaderState> = vec![];
                let alive = alive.clone();
                loop {
                    if !alive.load(Ordering::Relaxed) {
                        break;
                    }
                    loop_state = (|| {
                        let pcsc_context;
                        match loop_state.take() {
                            Some(c) => {
                                pcsc_context = c;
                            },
                            None => {
                                pcsc_context = match pcsc::Context::establish(pcsc::Scope::User) {
                                    Ok(p) => p,
                                    Err(e) => {
                                        log.log_err(loga::WARN, e.context("Error establishing pcsc context"));
                                        sleep(Duration::from_secs(1));
                                        return None;
                                    },
                                };
                                let mut reader_names = match pcsc_context.list_readers_owned() {
                                    Ok(r) => r,
                                    Err(e) => {
                                        log.log_err(loga::WARN, e.context("Error listing initial pcsc readers"));
                                        sleep(Duration::from_secs(1));
                                        return None;
                                    },
                                }.into_iter().collect::<HashSet<_>>();
                                reader_names.insert(pcsc::PNP_NOTIFICATION().to_owned());
                                let mut i = 0;
                                loop {
                                    if i >= watch.len() {
                                        break;
                                    }
                                    if reader_names.remove(&watch[i].name().to_owned()) {
                                        i += 1;
                                    } else {
                                        watch.remove(i);
                                    }
                                }
                                for new in &reader_names {
                                    watch.push(pcsc::ReaderState::new(new.clone(), pcsc::State::UNKNOWN));
                                }
                            },
                        }
                        match (|| {
                            match pcsc_context.get_status_change(Some(Duration::from_secs(1)), &mut watch) {
                                Ok(_) => { },
                                Err(pcsc::Error::ServiceStopped) | Err(pcsc::Error::NoService) => {
                                    // Windows will kill the SmartCard service when the last reader is disconnected
                                    return Ok(true);
                                },
                                Err(pcsc::Error::Timeout) => {
                                    return Ok(false);
                                },
                                Err(e) => return Err(e),
                            };
                            for reader_state in &mut watch {
                                shed!{
                                    'detect _;
                                    let old_state = reader_state.current_state();
                                    let new_state = reader_state.event_state();
                                    if !new_state.contains(pcsc::State::CHANGED) {
                                        break 'detect;
                                    }
                                    if reader_state.name() == pcsc::PNP_NOTIFICATION() {
                                        break 'detect;
                                    }
                                    if !old_state.contains(pcsc::State::PRESENT) &&
                                        new_state.contains(pcsc::State::PRESENT) {
                                        match (|| {
                                            // TODO https://gitlab.com/openpgp-card/openpgp-card/-/issues/72
                                            let Some(backend) = PcscBackend::card_backends(None)?.next() else {
                                                return Ok(());
                                            };
                                            let backend = backend?;
                                            let card = openpgp_card_sequoia::Card::<Open>::new(backend)?;
                                            stream_tx.blocking_send(card)?;
                                            return Ok(()) as Result<_, loga::Error>;
                                        })() {
                                            Ok(_) => (),
                                            Err(e) => {
                                                log.log_err(loga::WARN, e.context("Error handling card"));
                                            },
                                        }
                                    }
                                };
                                reader_state.sync_current_state();
                            }
                            return Ok(false);
                        })() {
                            Ok(clear) => if clear {
                                return None;
                            } else {
                                return Some(pcsc_context);
                            },
                            Err(e) => {
                                log.log_err(
                                    loga::WARN,
                                    e.context("Error waiting for next pcsc status change event"),
                                );
                                sleep(Duration::from_secs(1));
                                return Some(pcsc_context);
                            },
                        }
                    })();
                }
            }
        });
        return Self {
            alive: alive,
            rx: stream_rx,
        };
    }

    pub async fn next(&mut self) -> Option<openpgp_card_sequoia::Card<Open>> {
        return self.rx.recv().await;
    }
}

impl Drop for CardStream {
    fn drop(&mut self) {
        self.alive.store(false, Ordering::Relaxed);
    }
}

struct CardThread {
    decrypt_rx: mpsc::Receiver<Result<Vec<u8>, UiErr>>,
    decrypt_tx: mpsc::Sender<Vec<u8>>,
    need_touch_rx: mpsc::Receiver<()>,
    pin_rx: Option<oneshot::Receiver<Result<(), UiErr>>>,
    pin_tx: Option<oneshot::Sender<Option<String>>>,
}

pub struct CardThreadDecryptor(CardThread);

impl CardThreadDecryptor {
    pub async fn decrypt(mut self, body: Vec<u8>) -> Result<MaybeNeedTouch, UiErr> {
        self.0.decrypt_tx.send(body).await.unwrap();
        select!{
            _ = self.0.need_touch_rx.recv() => {
                return Ok(MaybeNeedTouch::NeedTouch(CardThreadNeedTouch(self.0)));
            }
            b = self.0.decrypt_rx.recv() => {
                return Ok(MaybeNeedTouch::Decryptor(CardThreadDecryptor(self.0), b.unwrap()?));
            }
        }
    }
}

pub struct CardThreadNeedPin(CardThread);

impl CardThreadNeedPin {
    pub async fn enter_pin(mut self, pin: Option<String>) -> Result<CardThreadDecryptor, UiErr> {
        self.0.pin_tx.take().unwrap().send(pin).unwrap();
        self.0.pin_rx.take().unwrap().await.unwrap()?;
        return Ok(CardThreadDecryptor(self.0));
    }
}

pub struct CardThreadNeedTouch(CardThread);

impl CardThreadNeedTouch {
    pub async fn wait_for_touch(mut self) -> Result<(CardThreadDecryptor, Vec<u8>), UiErr> {
        let b = self.0.decrypt_rx.recv().await.unwrap()?;
        return Ok((CardThreadDecryptor(self.0), b));
    }
}

fn chacha20poly1305_key(key: &[u8]) -> ChaCha20Poly1305 {
    return ChaCha20Poly1305::new(&<Sha256 as Digest>::digest(key));
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum Encrypted {
    V1(EncryptedV1),
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum EncryptedV1 {
    ChaCha20Poly1305 {
        body: Vec<u8>,
        nonce: chacha20poly1305::Nonce,
    },
}

pub async fn get_card_pubkey(
    mut card: openpgp_card_sequoia::Card<Open>,
) -> Result<(CardThreadNeedPin, PublicKey), UiErr> {
    let (resp_pubkey_tx, resp_pubkey_rx) = oneshot::channel();
    let (req_pin_tx, req_pin_rx) = oneshot::channel();
    let (resp_pin_tx, resp_pin_rx) = oneshot::channel();
    let (req_decrypt_tx, mut req_decrypt_rx) = mpsc::channel(1);
    let (resp_need_touch_tx, resp_need_touch_rx) = mpsc::channel(1);
    let (resp_decrypt_tx, resp_decrypt_rx) = mpsc::channel(1);
    std::thread::spawn(move || runtime::Builder::new_current_thread().build().unwrap().block_on(async move {
        let mut card_tx = match card.transaction().to_ui_err_external("Error starting card transaction") {
            Ok(c) => c,
            Err(e) => {
                _ = resp_pubkey_tx.send(Err(e));
                return;
            },
        };
        let pubkey =
            match card_tx
                .public_key(openpgp_card_sequoia::types::KeyType::Decryption)
                .to_ui_err_external("Error getting public key for card.") {
                Ok(p) => p,
                Err(e) => {
                    _ = resp_pubkey_tx.send(Err(e));
                    return;
                },
            };
        let Some(pubkey) = pubkey else {
            _ = resp_pubkey_tx.send(Err(UiErr::external("Card has no public key.")));
            return;
        };
        match resp_pubkey_tx.send(Ok(pubkey)) {
            Ok(_) => (),
            Err(_) => return,
        }
        let pin: Option<String> = match req_pin_rx.await {
            Ok(x) => x,
            Err(_) => return,
        };
        let mut card =
            match card_tx
                .to_user_card(pin.as_ref().map(|x| x.as_bytes()))
                .to_ui_err_external("Error unlocking card with entered PIN.") {
                Ok(c) => {
                    _ = resp_pin_tx.send(Ok(()));
                    c
                },
                Err(e) => {
                    _ = resp_pin_tx.send(Err(e));
                    return;
                },
            };
        let touch_cb = move || {
            _ = resp_need_touch_tx.try_send(());
        };
        let standard_policy = StandardPolicy::new();
        while let Some(mut message) = req_decrypt_rx.recv().await {
            let decryptor =
                match card.decryptor(&touch_cb).to_ui_err_external("Error requesting decryptor from card") {
                    Ok(c) => c,
                    Err(e) => {
                        _ = resp_decrypt_tx.send(Err(e));
                        return;
                    },
                };
            let mut message_cursor = Cursor::new(&mut message);
            let mut decrypted = vec![];
            let decryptor_builder =
                match DecryptorBuilder::from_reader(
                    &mut message_cursor,
                ).map_err(|e| UiErr::Internal(loga::err(e.to_string()))) {
                    Ok(d) => d,
                    Err(e) => {
                        _ = resp_decrypt_tx.send(Err(e)).await;
                        continue;
                    },
                };
            let mut decryptor_builder =
                match decryptor_builder
                    .with_policy(&standard_policy, None, decryptor)
                    .map_err(|e| UiErr::Internal(loga::err(e.to_string()))) {
                    Ok(d) => d,
                    Err(e) => {
                        _ = resp_decrypt_tx.send(Err(e)).await;
                        continue;
                    },
                };
            match std::io::copy(
                &mut decryptor_builder,
                &mut decrypted,
            ).to_ui_err_external("Error while decrypting data") {
                Ok(_) => (),
                Err(e) => {
                    _ = resp_decrypt_tx.send(Err(e));
                    continue;
                },
            }
            match resp_decrypt_tx.send(Ok(decrypted)).await {
                Ok(_) => (),
                Err(_) => return,
            }
        }
    }));
    let pubkey = resp_pubkey_rx.await.unwrap()?;
    return Ok((CardThreadNeedPin(CardThread {
        pin_tx: Some(req_pin_tx),
        pin_rx: Some(resp_pin_rx),
        decrypt_tx: req_decrypt_tx,
        need_touch_rx: resp_need_touch_rx,
        decrypt_rx: resp_decrypt_rx,
    }), pubkey));
}

pub fn local_decrypt(key: &[u8], encrypted: &[u8]) -> Result<Option<Vec<u8>>, loga::Error> {
    match serde_json::from_slice::<Encrypted>(&encrypted).context("Error parsing unencrypted body structure")? {
        Encrypted::V1(e) => match e {
            EncryptedV1::ChaCha20Poly1305 { nonce, body } => {
                return Ok(chacha20poly1305_key(key).decrypt(&nonce, body.as_ref()).ok().map(|x| x.to_vec()));
            },
        },
    }
}

pub fn local_encrypt(key: &[u8], body: &[u8]) -> Vec<u8> {
    let nonce = ChaCha20Poly1305::generate_nonce(&mut chacha20poly1305::aead::OsRng);
    return serde_json::to_vec(&Encrypted::V1(EncryptedV1::ChaCha20Poly1305 {
        body: chacha20poly1305_key(key).encrypt(&nonce, body).ok().unwrap().to_vec(),
        nonce: nonce,
    })).unwrap();
}

pub enum MaybeNeedTouch {
    Decryptor(CardThreadDecryptor, Vec<u8>),
    NeedTouch(CardThreadNeedTouch),
}

pub fn pgp_from_armor(key: &str) -> Result<sequoia_openpgp::Cert, loga::Error> {
    return Ok(
        sequoia_openpgp::Cert::from_reader(sequoia_openpgp::armor::Reader::from_reader(&mut key.as_bytes(), None))
            .map_err(loga::err)
            .context("Error reading key data as armored pgp cert")?,
    );
}

#[test]
fn test_local_crypt() {
    let key = &[0u8, 14, 222, 13, 197, 112, 123, 45];
    let body = "hello".as_bytes();
    let encrypted = local_encrypt(key, body);
    let decrypted = local_decrypt(key, &encrypted).expect("Must not have parse errors").expect("Must decrypt");
    assert_eq!(String::from_utf8(body.to_vec()).unwrap(), String::from_utf8(decrypted).unwrap());
}

/// Which token derivation scheme a factor tree's tokens and stored state use. See
/// `config::UnlockConfig` for the differences. New state is always produced with
/// `V2`; `Legacy` only exists so old databases can be unlocked and re-keyed.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum TokenScheme {
    Legacy,
    V2,
}

pub const TOKEN_LEN: usize = 32;
pub const KDF_SALT_LEN: usize = 16;

/// Stretch user-entered secret material (a password or recovery phrase) into a fixed
/// size token using argon2id. Parameters are above the OWASP minimum; memory use is
/// transient and only during unlock.
pub fn kdf_token(secret: &[u8], salt: &[u8]) -> Result<Vec<u8>, loga::Error> {
    let params =
        argon2::Params::new(64 * 1024, 3, 1, Some(TOKEN_LEN))
            .map_err(|e| loga::err(e.to_string()))
            .context("Error building kdf parameters")?;
    let argon = argon2::Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params);
    let mut out = vec![0u8; TOKEN_LEN];
    argon
        .hash_password_into(secret, salt, &mut out)
        .map_err(|e| loga::err(e.to_string()))
        .context("Error deriving token from secret")?;
    return Ok(out);
}

/// Combine child tokens for an `and` factor.
pub fn and_token(scheme: TokenScheme, children: &[&[u8]]) -> Vec<u8> {
    match scheme {
        TokenScheme::Legacy => {
            let mut token = vec![];
            for child in children {
                token.extend_from_slice(child);
            }
            return token;
        },
        TokenScheme::V2 => {
            let mut hasher = Sha256::new();
            for child in children {
                hasher.update((child.len() as u64).to_le_bytes());
                hasher.update(child);
            }
            return hasher.finalize().to_vec();
        },
    }
}

/// Turn the root token into the sqlcipher key string.
pub fn db_key(scheme: TokenScheme, root_token: &[u8]) -> String {
    match scheme {
        TokenScheme::Legacy => {
            // Passphrase; sqlcipher runs pbkdf2 on it
            return zbase32::encode_full_bytes(root_token);
        },
        TokenScheme::V2 => {
            // Raw key; all V2 root tokens are already uniformly random or kdf-stretched
            // 32 byte values, so skip sqlcipher's pbkdf2
            let mut out = String::with_capacity(TOKEN_LEN * 2 + 3);
            out.push_str("x'");
            for b in root_token {
                out.push_str(&format!("{:02x}", b));
            }
            out.push('\'');
            return out;
        },
    }
}

#[test]
fn test_db_key_v2_format() {
    let key = db_key(TokenScheme::V2, &[0u8; 32]);
    assert_eq!(key.len(), 67);
    assert!(key.starts_with("x'") && key.ends_with("'"));
}

#[test]
fn test_and_token_v2_unambiguous() {
    assert_ne!(and_token(TokenScheme::V2, &[b"ab", b"c"]), and_token(TokenScheme::V2, &[b"a", b"bc"]));
    assert_eq!(and_token(TokenScheme::Legacy, &[b"ab", b"c"]), and_token(TokenScheme::Legacy, &[b"a", b"bc"]));
}
