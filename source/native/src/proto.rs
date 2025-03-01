use {
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
    } else {
        return PathBuf::from(DEFAULT_SOCKET);
    }
}
