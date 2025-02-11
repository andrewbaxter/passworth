use {
    crate::datapath::SpecificPath,
    glove::reqresp,
    schemars::JsonSchema,
    serde::{
        Deserialize,
        Serialize,
    },
    std::{
        env,
        path::PathBuf,
    },
};

pub const DEFAULT_SOCKET: &str = "/run/passworth.sock";
pub const ENV_SOCKET: &str = "PASSWORTH_SOCK";

pub fn ipc_path() -> PathBuf {
    if let Some(v) = env::var_os(ENV_SOCKET) {
        return PathBuf::from(v);
    } else if let Some(v) = env::var_os("XDG_RUNTIME_DIR") {
        return PathBuf::from(v).join("passworth.sock");
    } else {
        return PathBuf::from(DEFAULT_SOCKET);
    }
}

#[derive(Serialize, Deserialize, Clone, JsonSchema)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum C2SGenerateVariant {
    Bytes {
        length: usize,
    },
    SafeAlphanumeric {
        length: usize,
    },
    Alphanumeric {
        length: usize,
    },
    AlphanumericSymbols {
        length: usize,
    },
    Pgp,
}
#[derive(Serialize, Deserialize, Clone, JsonSchema)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct ReqUnlock;
#[derive(Serialize, Deserialize, Clone, JsonSchema)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct ReqLock;

#[derive(Serialize, Deserialize, Clone, JsonSchema)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct ReqGet {
    pub paths: Vec<SpecificPath>,
    pub at: Option<i64>,
}

#[derive(Serialize, Deserialize, Clone, JsonSchema)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct ReqSet(pub Vec<(SpecificPath, serde_json::Value)>);

#[derive(Serialize, Deserialize, Clone, JsonSchema)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct ReqMove {
    pub from: SpecificPath,
    pub to: SpecificPath,
    pub overwrite: bool,
}

#[derive(Serialize, Deserialize, Clone, JsonSchema)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct ReqGenerate {
    pub path: SpecificPath,
    pub variant: C2SGenerateVariant,
    pub overwrite: bool,
}

#[derive(Serialize, Deserialize, Clone, JsonSchema)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct ReqPgpSign {
    pub key: SpecificPath,
    pub data: Vec<u8>,
}

#[derive(Serialize, Deserialize, Clone, JsonSchema)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct ReqPgpDecrypt {
    pub key: SpecificPath,
    pub data: Vec<u8>,
}

#[derive(Serialize, Deserialize, Clone, JsonSchema)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct ReqGetRevisions {
    pub paths: Vec<SpecificPath>,
    pub at: Option<i64>,
}

#[derive(Serialize, Deserialize, Clone, JsonSchema)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct ReqRevert {
    pub paths: Vec<SpecificPath>,
    pub at: i64,
}

reqresp!(pub msg {
    Unlock(ReqUnlock) =>(),
    Lock(ReqLock) =>(),
    Get(ReqGet) => serde_json:: Value,
    Set(ReqSet) =>(),
    Move(ReqMove) =>(),
    Generate(ReqGenerate) => String,
    PgpSign(ReqPgpSign) => Vec < u8 >,
    PgpDecrypt(ReqPgpDecrypt) => Vec < u8 >,
    GetRevisions(ReqGetRevisions) => serde_json:: Value,
    Revert(ReqRevert) =>(),
});
