use std::{
    env,
    io::Write,
};
use aargvark::{
    vark,
    Aargvark,
    AargvarkFile,
    AargvarkFromStr,
};
use loga::{
    ea,
    fatal,
    ResultContext,
    StandardFlag,
    StandardLog,
};
use passworth::{
    crypto::{
        get_card_pubkey,
        CardStream,
    },
    ioutil::{
        read_packet,
        write_packet,
    },
    proto::{
        C2SGenerateVariant,
        C2S,
        DEFAULT_SOCKET,
        ENV_SOCKET,
    },
};
use serde::de::DeserializeOwned;
use tokio::net::{
    UnixSocket,
    UnixStream,
};

struct PassworthPath(Vec<String>);

impl AargvarkFromStr for PassworthPath {
    fn from_str(s: &str) -> Result<Self, String> {
        return Ok(PassworthPath(serde_json::from_str(s).map_err(|e| e.to_string())?));
    }

    fn build_help_pattern(_state: &mut aargvark::HelpState) -> aargvark::HelpPattern {
        return aargvark::HelpPattern(vec![aargvark::HelpPatternElement::Type("JSON ARRAY[STRING]".to_string())]);
    }
}

struct PassworthSet((Vec<String>, serde_json::Value));

impl AargvarkFromStr for PassworthSet {
    fn from_str(s: &str) -> Result<Self, String> {
        return Ok(PassworthSet(serde_json::from_str(s).map_err(|e| e.to_string())?));
    }

    fn build_help_pattern(_state: &mut aargvark::HelpState) -> aargvark::HelpPattern {
        return aargvark::HelpPattern(
            vec![aargvark::HelpPatternElement::Type("JSON ARRAY[ARRAY[STRING], ANY]".to_string())],
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
enum Command {
    /// Trigger unlock and wait for it to complete.
    Unlock,
    /// Trigger lock and wait for it to complete.
    Lock,
    /// Unlock if locked, and retrieve the data at the following paths (merged into one
    /// JSON tree).
    Get {
        paths: Vec<PassworthPath>,
        /// Optionally retrieve data from a previous revision.
        at: Option<i64>,
    },
    /// Unlock if locked, and replace the data at the following paths.
    Set(Vec<PassworthSet>),
    /// Move data from one location to another.
    Move {
        from: PassworthPath,
        to: PassworthPath,
        /// If force is off and the destination path already has data, this will error.
        /// Setting force will override the data.
        overwrite: Option<()>,
    },
    /// Generate a secret and store it at the specified location - for asymmetric keys
    /// returns the public portion.
    Generate {
        /// Where to store the generated data.
        path: PassworthPath,
        /// What sort of data to generate.
        variant: GenerateVariant,
        /// Write the generated data even if data already exists at the path (overwrites
        /// path).
        overwrite: Option<()>,
    },
    /// Produce a pgp signature on data
    PgpSign {
        /// Path of key (in ascii-armor format) to sign with
        key: PassworthPath,
        /// Data to sign
        data: AargvarkFile,
    },
    /// Do pgp decryption on data
    PgpDecrypt {
        /// Path of key (in ascii-armor format) to decrypt with
        key: PassworthPath,
        /// Data to decrypt
        data: AargvarkFile,
    },
    /// List revision ids and timestamps for any values under the specified paths
    /// (merged into one JSON tree).
    ListRevisions {
        paths: Vec<PassworthPath>,
        /// Retrieve the revisions immediately before a previous revision.
        at: Option<i64>,
    },
    /// Restore data from a previous revision. Note that this preserves history, so you
    /// can restore to before the restore to undo a restore operation.
    Revert {
        paths: Vec<PassworthPath>,
        at: i64,
    },
    /// Listen for smartcards (usb and nfc) and show their fingerprints as can be used
    /// in config
    ScanCards,
}

async fn req<T: DeserializeOwned>(sock: &mut tokio::net::UnixStream, body: &C2S) -> Result<T, loga::Error> {
    write_packet(&mut *sock, &serde_json::to_vec(body).unwrap()).await?;
    return Ok(read_packet::<T>(sock).await.context("Connection closed by server before response")??);
}

async fn sock() -> Result<UnixStream, loga::Error> {
    let sock_path = env::var_os(ENV_SOCKET).unwrap_or(DEFAULT_SOCKET.into());
    let sock = UnixSocket::new_stream().context("Error allocating socket")?;
    return Ok(
        sock
            .connect(&sock_path)
            .await
            .context_with("Error connecting to passworth socket", ea!(path = sock_path.to_string_lossy()))?,
    );
}

async fn main2() -> Result<(), loga::Error> {
    let log = StandardLog::new().with_flags(&[StandardFlag::Error, StandardFlag::Warning, StandardFlag::Info]);
    match vark::<Command>() {
        Command::Unlock => {
            let mut stream = sock().await?;
            req::<()>(&mut stream, &C2S::Unlock).await?;
        },
        Command::Lock => {
            let mut stream = sock().await?;
            req::<()>(&mut stream, &C2S::Lock).await?;
        },
        Command::Get { paths, at } => {
            let mut stream = sock().await?;
            let res = req::<serde_json::Value>(&mut stream, &C2S::Get {
                paths: paths.into_iter().map(|x| x.0).collect(),
                at: at,
            }).await?;
            println!("{}", serde_json::to_string_pretty(&res).unwrap());
        },
        Command::Set(pairs) => {
            let mut stream = sock().await?;
            req::<()>(&mut stream, &C2S::Set(pairs.into_iter().map(|p| p.0).collect())).await?;
        },
        Command::Move { from, to, overwrite } => {
            let mut stream = sock().await?;
            req::<()>(&mut stream, &C2S::Move {
                from: from.0,
                to: to.0,
                overwrite: overwrite.is_some(),
            }).await?;
        },
        Command::Generate { path, variant, overwrite } => {
            let mut stream = sock().await?;
            let res = req::<String>(&mut stream, &C2S::Generate {
                path: path.0,
                variant: match variant {
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
                overwrite: overwrite.is_some(),
            }).await?;
            println!("{}", serde_json::to_string_pretty(&res).unwrap());
        },
        Command::PgpSign { key, data } => {
            let mut stream = sock().await?;
            let res = req::<Vec<u8>>(&mut stream, &C2S::PgpSign {
                key: key.0,
                data: data.value,
            }).await?;
            std::io::stdout().write_all(&res).unwrap();
            std::io::stdout().flush().unwrap();
        },
        Command::PgpDecrypt { key, data } => {
            let mut stream = sock().await?;
            let res = req::<Vec<u8>>(&mut stream, &C2S::PgpDecrypt {
                key: key.0,
                data: data.value,
            }).await?;
            std::io::stdout().write_all(&res).unwrap();
            std::io::stdout().flush().unwrap();
        },
        Command::ListRevisions { paths, at } => {
            let mut stream = sock().await?;
            let res = req::<serde_json::Value>(&mut stream, &C2S::GetRevisions {
                paths: paths.into_iter().map(|x| x.0).collect(),
                at: at,
            }).await?;
            println!("{}", serde_json::to_string_pretty(&res).unwrap());
        },
        Command::Revert { paths, at } => {
            let mut stream = sock().await?;
            req::<()>(&mut stream, &C2S::Revert {
                paths: paths.into_iter().map(|x| x.0).collect(),
                at: at,
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
                        log.log_err(StandardFlag::Warning, e.context("Error getting gpg key for card"));
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
