use std::{
    env,
    os::unix::net::UnixDatagram,
};
use aargvark::{
    vark,
    Aargvark,
    AargvarkFromStr,
};
use loga::{
    ea,
    fatal,
    ResultContext,
};
use passworth::proto::{
    C2S,
    DEFAULT_BUFFER,
    DEFAULT_SOCKET,
    ENV_BUFFER,
    ENV_SOCKET,
};
use serde::de::DeserializeOwned;

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
        at: Option<usize>,
    },
    /// Unlock if locked, and replace the data at the following paths.
    Set(Vec<PassworthSet>),
    /// List revision ids and timestamps for any values under the specified paths
    /// (merged into one JSON tree).
    ListRevisions {
        paths: Vec<PassworthPath>,
        /// Retrieve the revisions immediately before a previous revision.
        at: Option<usize>,
    },
    /// Restore data from a previous revision. Note that this preserves history, so you
    /// can restore to before the restore to undo a restore operation.
    Revert {
        paths: Vec<PassworthPath>,
        at: usize,
    },
}

fn req<T: DeserializeOwned>(sock: &UnixDatagram, body: &C2S) -> Result<T, loga::Error> {
    sock
        .send(&serde_json::to_vec(body).unwrap())
        .context_with("Error sending request", ea!(req = serde_json::to_string(&body).unwrap()))?;
    let buffer_size = match env::var_os(ENV_BUFFER) {
        Some(s) => usize::from_str_radix(
            &String::from_utf8_lossy(s.as_encoded_bytes()),
            10,
        ).context(format!("Failed to parse environment value {}", ENV_BUFFER))?,
        None => DEFAULT_BUFFER,
    };
    let mut buffer = Vec::new();
    buffer.resize(buffer_size, 0u8);
    let size =
        sock
            .recv(&mut buffer)
            .context_with("Error reading response to request", ea!(req = serde_json::to_string(&body).unwrap()))?;
    let resp = &buffer[..size];
    return Ok(
        serde_json::from_slice::<T>(
            resp,
        ).context_with(
            "Error parsing response to request",
            ea!(req = serde_json::to_string(&body).unwrap(), resp = String::from_utf8_lossy(&resp)),
        )?,
    );
}

fn main2() -> Result<(), loga::Error> {
    let sock_path = env::var_os(ENV_SOCKET).unwrap_or(DEFAULT_SOCKET.into());
    let sock = UnixDatagram::unbound().context("Error allocating socket")?;
    sock
        .connect(&sock_path)
        .context_with("Error connecting to passworth socket", ea!(path = sock_path.to_string_lossy()))?;
    match vark::<Command>() {
        Command::Unlock => {
            req::<()>(&sock, &C2S::Unlock)?;
        },
        Command::Lock => {
            req::<()>(&sock, &C2S::Lock)?;
        },
        Command::Get { paths, at } => {
            let res = req::<serde_json::Value>(&sock, &C2S::Get {
                paths: paths.into_iter().map(|x| x.0).collect(),
                at: at,
            })?;
            println!("{}", serde_json::to_string_pretty(&res).unwrap());
        },
        Command::Set(pairs) => {
            req::<()>(&sock, &C2S::Set(pairs.into_iter().map(|p| p.0).collect()))?;
        },
        Command::ListRevisions { paths, at } => {
            let res = req::<serde_json::Value>(&sock, &C2S::GetRevisions {
                paths: paths.into_iter().map(|x| x.0).collect(),
                at: at,
            })?;
            println!("{}", serde_json::to_string_pretty(&res).unwrap());
        },
        Command::Revert { paths, at } => {
            req::<()>(&sock, &C2S::Revert {
                paths: paths.into_iter().map(|x| x.0).collect(),
                at: at,
            })?;
        },
    }
    return Ok(());
}

fn main() {
    match main2() {
        Ok(_) => { },
        Err(e) => fatal(e),
    }
}
