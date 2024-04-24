use serde::{
    Deserialize,
    Serialize,
};

pub const DEFAULT_SOCKET: &str = "/run/passworth.sock";
pub const ENV_SOCKET: &str = "PASSWORTH_SOCK";
pub type PassPath = Vec<String>;

#[derive(Serialize, Deserialize, Clone)]
#[serde(rename_all = "snake_case")]
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

#[derive(Serialize, Deserialize, Clone)]
#[serde(rename_all = "snake_case")]
pub enum C2S {
    Unlock,
    Lock,
    Get {
        paths: Vec<PassPath>,
        at: Option<i64>,
    },
    Set(Vec<(PassPath, serde_json::Value)>),
    Move {
        from: PassPath,
        to: PassPath,
        overwrite: bool,
    },
    Generate {
        path: PassPath,
        variant: C2SGenerateVariant,
        overwrite: bool,
    },
    PgpSign {
        key: PassPath,
        data: Vec<u8>,
    },
    PgpDecrypt {
        key: PassPath,
        data: Vec<u8>,
    },
    GetRevisions {
        paths: Vec<PassPath>,
        at: Option<i64>,
    },
    Revert {
        paths: Vec<PassPath>,
        at: i64,
    },
}
