use {
    aargvark::{
        traits::AargvarkCompleter,
        traits_impls::{
            AargvarkFile,
            AargvarkFromStr,
            AargvarkJson,
        },
        vark,
        Aargvark,
    },
    async_tempfile::TempFile,
    loga::{
        ea,
        fatal,
        DebugDisplay,
        ErrContext,
        Log,
        ResultContext,
    },
    passworth::{
        datapath::SpecificPath,
        ipc::{
            self,
            C2SGenerateVariant,
            C2SGenerateVariantAlphanumeric,
            C2SGenerateVariantAlphanumericSymbols,
            C2SGenerateVariantBytes,
            C2SGenerateVariantSafeAlphanumeric,
        },
        utils::to_b32,
    },
    passworth_native::{
        crypto::{
            get_card_pubkey,
            CardStream,
        },
        proto::ipc_path,
    },
    std::{
        io::{
            stdin,
            Read,
            Write,
        },
        path::Path,
        str::FromStr,
    },
    tokio::{
        io::{
            AsyncReadExt,
            AsyncWriteExt,
        },
        task::spawn_blocking,
    },
};

async fn req<T: ipc::msg::ReqTrait>(body: T) -> Result<T::Resp, loga::Error> {
    return Ok(
        ipc::msg::Client::new(ipc_path()).await.map_err(loga::err)?.send_req(body).await.map_err(loga::err)?,
    );
}

fn remove_prefix(value: serde_json::Value, path: &SpecificPath) -> serde_json::Value {
    let mut value = value;
    for seg in &path.0 {
        match value {
            serde_json::Value::Object(mut o) => value = o.remove(seg).unwrap(),
            serde_json::Value::Null => {
                value = serde_json::Value::Null;
                break;
            },
            r => unreachable!("got {:?}", r),
        }
    }
    return value;
}

struct AargvarkSpecificPath(SpecificPath);

impl AargvarkFromStr for AargvarkSpecificPath {
    fn from_str(s: &str) -> Result<Self, String> {
        return Ok(AargvarkSpecificPath(SpecificPath::from_str(s).map_err(|e| e.to_string())?));
    }

    fn build_help_pattern(_state: &mut aargvark::help::HelpState) -> aargvark::help::HelpPattern {
        return aargvark::help::HelpPattern(
            vec![aargvark::help::HelpPatternElement::Type("PATH/TO/DATA".to_string())],
        );
    }

    fn build_completer(arg: &str) -> AargvarkCompleter {
        let arg = arg.to_string();
        return Box::new(move || {
            let Ok(mut path) = SpecificPath::from_str(&arg) else {
                return vec![];
            };
            let parent;
            let prefix;
            if path.0.is_empty() {
                prefix = "".to_string();
                parent = path;
            } else {
                prefix = path.0.pop().unwrap();
                parent = path;
            }
            let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
            let Ok(res) = rt.block_on(req(ipc::ReqMetaKeys {
                paths: vec![parent.clone()],
                at: None,
            })) else {
                return vec![];
            };
            let serde_json::Value::Object(res) = remove_prefix(res, &parent) else {
                return vec![];
            };
            let mut out = vec![];
            for (k, v) in res {
                if !k.starts_with(&prefix) {
                    continue;
                }
                let mut path = parent.clone();
                path.0.push(k.clone());

                // Add /a/b/c element
                out.push(vec![path.to_string()]);

                // Add `/a/b/c/` element 1. to prevent autocomplete from moving to next element,
                // 2. to indicate that the entry has children
                match v {
                    serde_json::Value::Object(_) => {
                        path.0.push("".to_string());
                        out.push(vec![path.to_string()]);
                    },
                    _ => { },
                }
            }
            return out;
        });
    }
}

#[derive(Aargvark)]
struct GenerateVariantBytes {
    length: usize,
}

#[derive(Aargvark)]
struct GenerateVariantSafeAlphanumeric {
    length: usize,
}

#[derive(Aargvark)]
struct GenerateVariantAlphanumeric {
    length: usize,
}

#[derive(Aargvark)]
struct GenerateVariantAlphanumericSymbols {
    length: usize,
}

#[derive(Aargvark)]
enum GenerateVariant {
    /// Generate random bytes, encoded as zbase32
    Bytes(GenerateVariantBytes),
    /// Generate a password with a shorter visually-unambiguous, case-insensitive
    /// alphanumeric characters.
    SafeAlphanumeric(GenerateVariantSafeAlphanumeric),
    /// Generate a password using upper and lowercase alphanumeric values.
    Alphanumeric(GenerateVariantAlphanumeric),
    /// Generate a password using upper and lowercase alphanumeric values and symbols.
    AlphanumericSymbols(GenerateVariantAlphanumericSymbols),
    /// Generate a PGP key.
    Pgp,
    /// Generate an SSH key.
    Ssh,
}

#[derive(Aargvark)]
struct ReadCommand {
    /// A path to get data for, in `/path/to/data` format.
    path: AargvarkSpecificPath,
    /// Optionally retrieve the latest data at or before a previous revision id.
    revision: Option<i64>,
    /// Output json encoded data rather than de-quoting strings. This also allows
    /// outputting a root null value.
    json: Option<()>,
}

#[derive(Aargvark)]
struct MetaKeysCommand {
    /// A path to get keys for, in `/path/to/data` format.
    path: AargvarkSpecificPath,
    /// Optionally retrieve the latest data at or before a previous revision id.
    revision: Option<i64>,
}

#[derive(Aargvark)]
struct MetaPgpPubkeyCommand {
    /// Path to the private key.
    path: AargvarkSpecificPath,
    /// Optionally retrieve the latest data at or before a previous revision id.
    revision: Option<i64>,
}

#[derive(Aargvark)]
struct MetaSshPubkeyCommand {
    /// Path to the private key.
    path: AargvarkSpecificPath,
    /// Optionally retrieve the latest data at or before a previous revision id.
    revision: Option<i64>,
}

#[derive(Aargvark)]
struct WriteCommand {
    /// Path to create/overwrite
    path: AargvarkSpecificPath,
    /// Input is already JSON so add directly rather than encode as JSON string
    json: Option<()>,
    /// Input is binary, store as a B64 JSON string
    binary: Option<()>,
}

#[derive(Aargvark)]
struct WriteEditCommand {
    /// Path to create/overwrite
    path: AargvarkSpecificPath,
}

#[derive(Aargvark)]
struct WriteMoveCommand {
    from: AargvarkSpecificPath,
    to: AargvarkSpecificPath,
    /// If force is off and the destination path already has data, this will error.
    /// Setting force will override the data.
    overwrite: Option<()>,
}

#[derive(Aargvark)]
struct WriteGenerateCommand {
    /// Where to store the generated data.
    path: AargvarkSpecificPath,
    /// What sort of data to generate.
    variant: GenerateVariant,
    /// Write the generated data even if data already exists at the path (overwrites
    /// path).
    overwrite: Option<()>,
}

#[derive(Aargvark)]
struct DerivePgpSignCommand {
    /// Path of key (in ascii-armor format) to sign with
    key: AargvarkSpecificPath,
    /// Data to sign.
    data: AargvarkFile,
}

#[derive(Aargvark)]
struct DerivePgpDecryptCommand {
    /// Path of key (in ascii-armor format) to decrypt with
    key: AargvarkSpecificPath,
    /// Data to decrypt.
    data: AargvarkFile,
}

#[derive(Aargvark)]
struct DeriveOtpCommand {
    /// Path of key (in `otpauth://` format) to decrypt with
    key: AargvarkSpecificPath,
}

#[derive(Aargvark)]
struct ListRevisionsCommand {
    /// Retrieve the revision ids of the data at each path.
    paths: Vec<AargvarkSpecificPath>,
    /// Retrieve the revision data at a specific revision.
    revision: Option<i64>,
}

#[derive(Aargvark)]
struct RevertCommand {
    /// Revert the data at the specified paths to their value at or before the
    /// specified revision.
    paths: Vec<AargvarkSpecificPath>,
    /// The revision id.
    #[vark(flag = "--revision")]
    revision: i64,
}

#[derive(Aargvark)]
#[vark(break_help)]
enum Command {
    /// Execute a JSON IPC command directly (see ipc jsonschema).
    Json(AargvarkJson<ipc::msg::Req>),
    /// Trigger unlock and wait for it to complete.
    Unlock,
    /// Trigger lock and wait for it to complete.
    Lock,
    /// Unlock if locked, and retrieve the keys at the following paths (merged into one
    /// JSON tree). The tree is basically the same as in "get" but where all leaf
    /// values are `null`.
    MetaKeys(MetaKeysCommand),
    /// Unlock if locked and retrieve the public key for the ascii-armored pgp key at
    /// the specified path.
    MetaPgpPubkey(MetaPgpPubkeyCommand),
    /// Unlock if locked and retrieve the public key for the PEM SSH key at the
    /// specified path.
    MetaSshPubkey(MetaSshPubkeyCommand),
    /// Unlock if locked, and retrieve the data at the following paths (merged into one
    /// JSON tree). Errors if no data found (null output) unless the `--json` flag is
    /// used.
    Read(ReadCommand),
    /// List revision ids and timestamps for any values under the specified paths
    /// (merged into one JSON tree).
    ReadRevisions(ListRevisionsCommand),
    /// Unlock if locked, and replace the data at the following paths. The data is read
    /// from stdin.
    Write(WriteCommand),
    /// Create or edit a value using the editor you have configured in `SECURE_EDITOR`.
    /// The data is edited as JSON, however invalid JSON will be converted to a string
    /// value. The editor is given a temporary file with the current secret data as its
    /// first argument, and the contents of the file will be stored if it exits with no
    /// error.
    WriteEdit(WriteEditCommand),
    /// Move data from one location to another.
    WriteMove(WriteMoveCommand),
    /// Generate a secret and store it at the specified location - for asymmetric keys
    /// returns the public portion.
    WriteGenerate(WriteGenerateCommand),
    /// Restore data from a previous revision. Note that this preserves history, so you
    /// can restore to before the restore to undo a restore operation.
    WriteRevert(RevertCommand),
    /// Produce a detached pgp signature on data using a stored key.
    DerivePgpSign(DerivePgpSignCommand),
    /// Do pgp decryption on data using a stored key.
    DerivePgpDecrypt(DerivePgpDecryptCommand),
    /// Generate an otp token from a stored `otpauth://` url.
    DeriveOtp(DeriveOtpCommand),
    /// Listen for smartcards (usb and nfc) and show their fingerprints in a format
    /// that can be used for config.
    ScanCards,
}

async fn main2() -> Result<(), loga::Error> {
    let log = Log::new_root(loga::INFO);
    match spawn_blocking(|| vark::<Command>()).await.unwrap() {
        Command::Json(args) => {
            let resp =
                ipc::msg::Client::new(ipc_path())
                    .await
                    .map_err(loga::err)?
                    .send_req_enum(&args.value)
                    .await
                    .map_err(loga::err)?;
            println!(
                "{}",
                serde_json::to_string_pretty(
                    &serde_json::from_slice::<serde_json::Value>(
                        &resp,
                    ).context_with("Received invalid JSON response", ea!(resp = String::from_utf8_lossy(&resp)))?,
                ).unwrap()
            );
        },
        Command::Unlock => {
            req(ipc::ReqLock(ipc::LockAction::Unlock)).await?;
        },
        Command::Lock => {
            req(ipc::ReqLock(ipc::LockAction::Lock)).await?;
        },
        Command::MetaKeys(args) => {
            let mut res = req(ipc::ReqMetaKeys {
                paths: vec![args.path.0.clone()],
                at: args.revision,
            }).await?;

            // Remove prefix on data
            res = remove_prefix(res, &args.path.0);

            // Output
            println!("{}", serde_json::to_string_pretty(&res).unwrap());
        },
        Command::MetaPgpPubkey(args) => {
            let res = req(ipc::ReqMetaPgpPubkey {
                path: args.path.0,
                at: args.revision,
            }).await?;
            println!("{}", res);
        },
        Command::MetaSshPubkey(args) => {
            let res = req(ipc::ReqMetaSshPubkey {
                path: args.path.0,
                at: args.revision,
            }).await?;
            println!("{}", res);
        },
        Command::Read(args) => {
            let mut res = req(ipc::ReqRead {
                paths: vec![args.path.0.clone()],
                at: args.revision,
            }).await?;

            // Remove prefix on data
            res = remove_prefix(res, &args.path.0);

            // Output
            match (args.json.is_some(), &res) {
                (false, serde_json::Value::String(v)) => {
                    println!("{}", v);
                },
                (false, serde_json::Value::Null) => {
                    return Err(loga::err("No value found."));
                },
                (_, res) => {
                    println!("{}", serde_json::to_string_pretty(&res).unwrap());
                },
            }
        },
        Command::ReadRevisions(args) => {
            let res = req(ipc::ReqMetaRevisions {
                paths: args.paths.into_iter().map(|x| x.0).collect(),
                at: args.revision,
            }).await?;
            println!("{}", serde_json::to_string_pretty(&res).unwrap());
        },
        Command::Write(args) => {
            let mut data = Vec::new();
            stdin().read_to_end(&mut data).context("Error reading stdin")?;
            let data = if args.json.is_some() {
                serde_json::from_slice(&data).context("Error parsing set value as JSON")?
            } else if args.binary.is_some() {
                serde_json::Value::String(to_b32(&data))
            } else {
                serde_json::Value::String(String::from_utf8(data).context("Error parsing value as UTF-8")?)
            };
            req(ipc::ReqWrite(vec![(args.path.0, data)])).await?;
        },
        Command::WriteEdit(args) => {
            const ENV_EDITOR: &str = "SECURE_EDITOR";
            let Some(editor) = std::env::var_os(ENV_EDITOR) else {
                return Err(loga::err_with("Missing secure editor environment variable", ea!(env = ENV_EDITOR)));
            };

            // Get existing data
            let mut res = req(ipc::ReqRead {
                paths: vec![args.path.0.clone()],
                at: None,
            }).await?;

            // Remove prefix on data
            res = remove_prefix(res, &args.path.0);

            // Store in tempfile
            let run_dir = if let Some(dir) = std::env::var_os("XDG_RUNTIME_DIR") {
                dir
            } else {
                "/run".into()
            };
            let t = TempFile::new_in(Path::new(&run_dir)).await.context("Error creating temp file")?;
            t
                .open_rw()
                .await
                .context("Error opening temp file")?
                .write_all(&serde_json::to_vec_pretty(&res).unwrap())
                .await
                .context_with(
                    "Error writing secret to temporary file for editing",
                    ea!(path = t.file_path().dbg_str()),
                )?;
            t.sync_all().await.context("Error flushing data")?;

            // Edit it
            let mut c = tokio::process::Command::new(editor);
            c.arg(t.file_path());
            c.output().await.context_with("Error editing secret", ea!(command = c.dbg_str()))?;

            // Save result
            let mut data = vec![];
            t.sync_all().await.context("Error flushing data")?;
            t
                .open_ro()
                .await
                .context("Error opening secret to read back")?
                .read_to_end(&mut data)
                .await
                .context("Error reading modified secret data")?;
            let data = match serde_json::from_slice::<serde_json::Value>(&data) {
                Ok(d) => d,
                Err(e) => {
                    log.log_err(
                        loga::WARN,
                        e.context("Modified secret was not valid JSON - converting to JSON string before writing"),
                    );
                    match String::from_utf8(data.clone()) {
                        Ok(d) => {
                            serde_json::Value::String(d)
                        },
                        Err(e) => {
                            log.log_err(
                                loga::WARN,
                                e.context(
                                    "Modified secret was not valid UTF-8 - converting to base-32 encoded JSON string before writing",
                                ),
                            );
                            serde_json::Value::String(to_b32(&data))
                        },
                    }
                },
            };
            req(ipc::ReqWrite(vec![(args.path.0, data)])).await?;
        },
        Command::WriteMove(args) => {
            req(ipc::ReqWriteMove {
                from: args.from.0,
                to: args.to.0,
                overwrite: args.overwrite.is_some(),
            }).await?;
        },
        Command::WriteRevert(args) => {
            req(ipc::ReqWriteRevert {
                paths: args.paths.into_iter().map(|x| x.0).collect(),
                at: args.revision,
            }).await?;
        },
        Command::WriteGenerate(args) => {
            req(ipc::ReqWriteGenerate {
                path: args.path.0,
                variant: match args.variant {
                    GenerateVariant::Bytes(args) => C2SGenerateVariant::Bytes(
                        C2SGenerateVariantBytes { length: args.length },
                    ),
                    GenerateVariant::SafeAlphanumeric(args) => C2SGenerateVariant::SafeAlphanumeric(
                        C2SGenerateVariantSafeAlphanumeric { length: args.length },
                    ),
                    GenerateVariant::Alphanumeric(args) => C2SGenerateVariant::Alphanumeric(
                        C2SGenerateVariantAlphanumeric { length: args.length },
                    ),
                    GenerateVariant::AlphanumericSymbols(args) => C2SGenerateVariant::AlphanumericSymbols(
                        C2SGenerateVariantAlphanumericSymbols { length: args.length },
                    ),
                    GenerateVariant::Pgp => C2SGenerateVariant::Pgp,
                    GenerateVariant::Ssh => C2SGenerateVariant::Ssh,
                },
                overwrite: args.overwrite.is_some(),
            }).await?;
        },
        Command::DerivePgpSign(args) => {
            let res = req(ipc::ReqDerivePgpSign {
                key: args.key.0,
                data: args.data.value,
            }).await?;
            std::io::stdout().write_all(res.as_bytes()).unwrap();
            std::io::stdout().flush().unwrap();
        },
        Command::DerivePgpDecrypt(args) => {
            let res = req(ipc::ReqDerivePgpDecrypt {
                key: args.key.0,
                data: args.data.value,
            }).await?;
            std::io::stdout().write_all(&res).unwrap();
            std::io::stdout().flush().unwrap();
        },
        Command::DeriveOtp(args) => {
            let res = req(ipc::ReqDeriveOtp { key: args.key.0 }).await?;
            std::io::stdout().write_all(res.as_bytes()).unwrap();
            std::io::stdout().flush().unwrap();
        },
        Command::ScanCards => {
            let mut card_stream = CardStream::new(&log);
            while let Some(card) = card_stream.next().await {
                let (_, pubkey) = match get_card_pubkey(card).await {
                    Ok(x) => x,
                    Err(e) => {
                        let e = match e {
                            passworth_native::error::UiErr::Internal(i) => i,
                            passworth_native::error::UiErr::External(e, i) => {
                                i.unwrap_or(loga::err(&e))
                            },
                            passworth_native::error::UiErr::InternalUnresolvable(e) => e,
                        };
                        log.log_err(loga::WARN, e.context("Error getting gpg key for card"));
                        continue;
                    },
                };
                println!("Found card {}", pubkey.fingerprint().to_hex());
            }
        },
    }
    return Ok(());
}

#[tokio::main(flavor = "current_thread")]
async fn main() {
    match main2().await {
        Ok(_) => { },
        Err(e) => fatal(e),
    }
}
