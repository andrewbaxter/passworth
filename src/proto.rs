use serde::{
    Deserialize,
    Serialize,
};

pub const DEFAULT_SOCKET: &str = "/run/passworth.sock";
pub const ENV_SOCKET: &str = "PASSWORTH_SOCK";
pub const DEFAULT_BUFFER: usize = 
    // B
    1024 * 
        // KiB
        1024 * 
        // MiB
        4;
pub const ENV_BUFFER: &str = "PASSWORTH_BUFFER";

#[derive(Serialize, Deserialize, Clone)]
#[serde(rename_all = "snake_case")]
pub enum C2S {
    Unlock,
    Lock,
    Get {
        paths: Vec<Vec<String>>,
        at: Option<usize>,
    },
    Set(Vec<(Vec<String>, serde_json::Value)>),
    GetRevisions {
        paths: Vec<Vec<String>>,
        at: Option<usize>,
    },
    Revert {
        paths: Vec<Vec<String>>,
        at: usize,
    },
}
