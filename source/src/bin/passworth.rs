use {
    aargvark::{
        traits_impls::{
            AargvarkFile,
            AargvarkFromStr,
        },
        vark,
        Aargvark,
    },
    loga::{
        fatal,
        Log,
    },
    passworth::{
        crypto::{
            get_card_pubkey,
            CardStream,
        },
        proto::{
            self,
            ipc_path,
            C2SGenerateVariant,
        },
    },
    std::{
        io::Write,
    },
};

struct PassworthPath(Vec<String>);

impl AargvarkFromStr for PassworthPath {
    fn from_str(s: &str) -> Result<Self, String> {
        return Ok(PassworthPath(serde_json::from_str(s).map_err(|e| e.to_string())?));
    }

    fn build_help_pattern(_state: &mut aargvark::help::HelpState) -> aargvark::help::HelpPattern {
        return aargvark::help::HelpPattern(
            vec![aargvark::help::HelpPatternElement::Type("JSON ARRAY[STRING]".to_string())],
        );
    }
}

struct PassworthSet((Vec<String>, serde_json::Value));

impl AargvarkFromStr for PassworthSet {
    fn from_str(s: &str) -> Result<Self, String> {
        return Ok(PassworthSet(serde_json::from_str(s).map_err(|e| e.to_string())?));
    }

    fn build_help_pattern(_state: &mut aargvark::help::HelpState) -> aargvark::help::HelpPattern {
        return aargvark::help::HelpPattern(
            vec![aargvark::help::HelpPatternElement::Type("JSON ARRAY[ARRAY[STRING], ANY]".to_string())],
        );
    }
}

#[derive(Aargvark)]
enum GenerateVariant {
    /// Generate random bytes, encoded as base664
    Bytes {
        length: usize,
    },
    /// Generate a password with a shorter visually-unambiguous, case-insensitive
    /// alphabet.
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
    paths: Vec<PassworthPath>,
    /// Optionally retrieve data from a previous revision.
    at: Option<i64>,
    /// Extract primitive value from json - i.e. unquote strings, do nothing for
    /// numbers and bools. Errors if not primitive.
    extract: Option<()>,
}

#[derive(Aargvark)]
struct MoveCommand {
    from: PassworthPath,
    to: PassworthPath,
    /// If force is off and the destination path already has data, this will error.
    /// Setting force will override the data.
    overwrite: Option<()>,
}

#[derive(Aargvark)]
struct GenerateCommand {
    /// Where to store the generated data.
    path: PassworthPath,
    /// What sort of data to generate.
    variant: GenerateVariant,
    /// Write the generated data even if data already exists at the path (overwrites
    /// path).
    overwrite: Option<()>,
}

#[derive(Aargvark)]
struct PgpSignCommand {
    /// Path of key (in ascii-armor format) to sign with
    key: PassworthPath,
    /// Data to sign
    data: AargvarkFile,
}

#[derive(Aargvark)]
struct PgpDecryptCommand {
    /// Path of key (in ascii-armor format) to decrypt with
    key: PassworthPath,
    /// Data to decrypt
    data: AargvarkFile,
}

#[derive(Aargvark)]
struct ListRevisionsCommand {
    paths: Vec<PassworthPath>,
    /// Retrieve the revisions immediately before a previous revision.
    at: Option<i64>,
}

#[derive(Aargvark)]
struct RevertCommand {
    paths: Vec<PassworthPath>,
    at: i64,
}

#[derive(Aargvark)]
#[vark(break_help)]
enum Command {
    /// Trigger unlock and wait for it to complete.
    Unlock,
    /// Trigger lock and wait for it to complete.
    Lock,
    /// Unlock if locked, and retrieve the data at the following paths (merged into one
    /// JSON tree).
    Get(GetCommand),
    /// Unlock if locked, and replace the data at the following paths.
    Set(Vec<PassworthSet>),
    /// Move data from one location to another.
    Move(MoveCommand),
    /// Generate a secret and store it at the specified location - for asymmetric keys
    /// returns the public portion.
    Generate(GenerateCommand),
    /// Produce a pgp signature on data
    PgpSign(PgpSignCommand),
    /// Do pgp decryption on data
    PgpDecrypt(PgpDecryptCommand),
    /// List revision ids and timestamps for any values under the specified paths
    /// (merged into one JSON tree).
    ListRevisions(ListRevisionsCommand),
    /// Restore data from a previous revision. Note that this preserves history, so you
    /// can restore to before the restore to undo a restore operation.
    Revert(RevertCommand),
    /// Listen for smartcards (usb and nfc) and show their fingerprints as can be used
    /// in config
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
        Command::Unlock => {
            req(proto::ReqUnlock).await?;
        },
        Command::Lock => {
            req(proto::ReqLock).await?;
        },
        Command::Get(args) => {
            let res = req(proto::ReqGet {
                paths: args.paths.into_iter().map(|x| x.0).collect(),
                at: args.at,
            }).await?;
            if args.extract.is_some() {
                match &res {
                    serde_json::Value::Null => {
                        print!("null");
                    },
                    serde_json::Value::Bool(v) => {
                        print!("{}", v);
                    },
                    serde_json::Value::Number(number) => {
                        print!("{}", number);
                    },
                    serde_json::Value::String(v) => {
                        print!("{}", v);
                    },
                    serde_json::Value::Array(_) | serde_json::Value::Object(_) => {
                        return Err(
                            loga::err(
                                format!(
                                    "Got non-primitive value, can't extract: {}",
                                    serde_json::to_string(&res).unwrap()
                                ),
                            ),
                        );
                    },
                }
            } else {
                println!("{}", serde_json::to_string_pretty(&res).unwrap());
            }
        },
        Command::Set(pairs) => {
            req(proto::ReqSet(pairs.into_iter().map(|p| p.0).collect())).await?;
        },
        Command::Move(args) => {
            req(proto::ReqMove {
                from: args.from.0,
                to: args.to.0,
                overwrite: args.overwrite.is_some(),
            }).await?;
        },
        Command::Generate(args) => {
            let res = req(proto::ReqGenerate {
                path: args.path.0,
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
                key: args.key.0,
                data: args.data.value,
            }).await?;
            std::io::stdout().write_all(&res).unwrap();
            std::io::stdout().flush().unwrap();
        },
        Command::PgpDecrypt(args) => {
            let res = req(proto::ReqPgpDecrypt {
                key: args.key.0,
                data: args.data.value,
            }).await?;
            std::io::stdout().write_all(&res).unwrap();
            std::io::stdout().flush().unwrap();
        },
        Command::ListRevisions(args) => {
            let res = req(proto::ReqGetRevisions {
                paths: args.paths.into_iter().map(|x| x.0).collect(),
                at: args.at,
            }).await?;
            println!("{}", serde_json::to_string_pretty(&res).unwrap());
        },
        Command::Revert(args) => {
            req(proto::ReqRevert {
                paths: args.paths.into_iter().map(|x| x.0).collect(),
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
