use {
    aargvark::{
        traits_impls::{
            AargvarkFile,
            AargvarkJson,
        },
        vark,
        Aargvark,
    },
    loga::{
        ea,
        fatal,
        Log,
        ResultContext,
    },
    passworth::{
        crypto::{
            get_card_pubkey,
            CardStream,
        },
        datapath::SpecificPath,
        proto::{
            self,
            ipc_path,
            C2SGenerateVariant,
        },
    },
    std::io::Write,
};

#[derive(Aargvark)]
enum GenerateVariant {
    /// Generate random bytes, encoded as base64
    Bytes {
        length: usize,
    },
    /// Generate a password with a shorter visually-unambiguous, case-insensitive
    /// alphanumeric characters.
    SafeAlphanumeric {
        length: usize,
    },
    /// Generate a password using upper and lowercase alphanumeric values.
    Alphanumeric {
        length: usize,
    },
    /// Generate a password using upper and lowercase alphanumeric values and symbols.
    AlphanumericSymbols {
        length: usize,
    },
    /// Generate a PGP key.
    Pgp,
}

#[derive(Aargvark)]
struct GetCommand {
    /// A path to get data for, in `/path/to/data` format.
    path: SpecificPath,
    /// Optionally retrieve the latest data at or before a previous revision id.
    at: Option<i64>,
    /// Output json encoded data rather than de-quoting strings.
    json: Option<()>,
}

#[derive(Aargvark)]
struct SetCommand {
    /// Path to create/overwrite
    path: SpecificPath,
    /// JSON data to set at path. Setting to null will delete the data.
    value: String,
}

#[derive(Aargvark)]
struct MoveCommand {
    from: SpecificPath,
    to: SpecificPath,
    /// If force is off and the destination path already has data, this will error.
    /// Setting force will override the data.
    overwrite: Option<()>,
}

#[derive(Aargvark)]
struct GenerateCommand {
    /// Where to store the generated data.
    path: SpecificPath,
    /// What sort of data to generate.
    variant: GenerateVariant,
    /// Write the generated data even if data already exists at the path (overwrites
    /// path).
    overwrite: Option<()>,
}

#[derive(Aargvark)]
struct PgpSignCommand {
    /// Path of key (in ascii-armor format) to sign with
    key: SpecificPath,
    /// Data to sign.
    data: AargvarkFile,
}

#[derive(Aargvark)]
struct PgpDecryptCommand {
    /// Path of key (in ascii-armor format) to decrypt with
    key: SpecificPath,
    /// Data to decrypt.
    data: AargvarkFile,
}

#[derive(Aargvark)]
struct ListRevisionsCommand {
    /// Retrieve the revision ids of the data at each path.
    paths: Vec<SpecificPath>,
    /// Retrieve the revisions immediately before a previous revision.
    at: Option<i64>,
}

#[derive(Aargvark)]
struct RevertCommand {
    /// Revert the data at the specified paths to their value at or before the
    /// specified revision.
    paths: Vec<SpecificPath>,
    /// The revision id.
    at: i64,
}

#[derive(Aargvark)]
#[vark(break_help)]
enum Command {
    /// Execute a JSON IPC command directly (see ipc jsonschema).
    Json(AargvarkJson<proto::msg::Req>),
    /// Trigger unlock and wait for it to complete.
    Unlock,
    /// Trigger lock and wait for it to complete.
    Lock,
    /// Unlock if locked, and retrieve the data at the following paths (merged into one
    /// JSON tree).
    Get(GetCommand),
    /// Unlock if locked, and replace the data at the following paths.
    Set(SetCommand),
    /// Move data from one location to another.
    Move(MoveCommand),
    /// Generate a secret and store it at the specified location - for asymmetric keys
    /// returns the public portion.
    Generate(GenerateCommand),
    /// Produce a pgp signature on data using a stored key.
    PgpSign(PgpSignCommand),
    /// Do pgp decryption on data using a stored key.
    PgpDecrypt(PgpDecryptCommand),
    /// List revision ids and timestamps for any values under the specified paths
    /// (merged into one JSON tree).
    ListRevisions(ListRevisionsCommand),
    /// Restore data from a previous revision. Note that this preserves history, so you
    /// can restore to before the restore to undo a restore operation.
    Revert(RevertCommand),
    /// Listen for smartcards (usb and nfc) and show their fingerprints in a format
    /// that can be used for config.
    ScanCards,
}

async fn req<T: proto::msg::ReqTrait>(body: T) -> Result<T::Resp, loga::Error> {
    return Ok(
        proto::msg::Client::new(ipc_path()).await.map_err(loga::err)?.send_req(body).await.map_err(loga::err)?,
    );
}

async fn main2() -> Result<(), loga::Error> {
    let log = Log::new_root(loga::INFO);
    match vark::<Command>() {
        Command::Json(args) => {
            let resp =
                proto::msg::Client::new(ipc_path())
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
            req(proto::ReqUnlock).await?;
        },
        Command::Lock => {
            req(proto::ReqLock).await?;
        },
        Command::Get(args) => {
            let res = req(proto::ReqGet {
                paths: vec![args.path],
                at: args.at,
            }).await?;
            match (args.json.is_some(), &res) {
                (false, serde_json::Value::String(v)) => {
                    println!("{}", v);
                },
                (_, res) => {
                    println!("{}", serde_json::to_string_pretty(&res).unwrap());
                },
            }
        },
        Command::Set(args) => {
            req(
                proto::ReqSet(
                    vec![(args.path, serde_json::from_str(&args.value).context("Error parsing set value as JSON")?)],
                ),
            ).await?;
        },
        Command::Move(args) => {
            req(proto::ReqMove {
                from: args.from,
                to: args.to,
                overwrite: args.overwrite.is_some(),
            }).await?;
        },
        Command::Generate(args) => {
            let res = req(proto::ReqGenerate {
                path: args.path,
                variant: match args.variant {
                    GenerateVariant::Bytes { length } => C2SGenerateVariant::Bytes { length: length },
                    GenerateVariant::SafeAlphanumeric { length } => C2SGenerateVariant::SafeAlphanumeric {
                        length: length,
                    },
                    GenerateVariant::Alphanumeric { length } => C2SGenerateVariant::Alphanumeric { length: length },
                    GenerateVariant::AlphanumericSymbols { length } => C2SGenerateVariant::AlphanumericSymbols {
                        length: length,
                    },
                    GenerateVariant::Pgp => C2SGenerateVariant::Pgp,
                },
                overwrite: args.overwrite.is_some(),
            }).await?;
            println!("{}", serde_json::to_string_pretty(&res).unwrap());
        },
        Command::PgpSign(args) => {
            let res = req(proto::ReqPgpSign {
                key: args.key,
                data: args.data.value,
            }).await?;
            std::io::stdout().write_all(&res).unwrap();
            std::io::stdout().flush().unwrap();
        },
        Command::PgpDecrypt(args) => {
            let res = req(proto::ReqPgpDecrypt {
                key: args.key,
                data: args.data.value,
            }).await?;
            std::io::stdout().write_all(&res).unwrap();
            std::io::stdout().flush().unwrap();
        },
        Command::ListRevisions(args) => {
            let res = req(proto::ReqGetRevisions {
                paths: args.paths,
                at: args.at,
            }).await?;
            println!("{}", serde_json::to_string_pretty(&res).unwrap());
        },
        Command::Revert(args) => {
            req(proto::ReqRevert {
                paths: args.paths,
                at: args.at,
            }).await?;
        },
        Command::ScanCards => {
            let mut card_stream = CardStream::new(&log);
            while let Some(card) = card_stream.next().await {
                let (_, pubkey) = match get_card_pubkey(card).await {
                    Ok(x) => x,
                    Err(e) => {
                        let e = match e {
                            passworth::error::UiErr::Internal(i) => i,
                            passworth::error::UiErr::External(e, i) => {
                                i.unwrap_or(loga::err(&e))
                            },
                            passworth::error::UiErr::InternalUnresolvable(e) => e,
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
