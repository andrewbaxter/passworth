pub mod v1;

pub use v1 as latest;
use {
    good_ormning::runtime::sqlite::GoodOrmningCustomString,
    schemars::JsonSchema,
    serde::{
        Deserialize,
        Serialize,
    },
};

#[derive(Serialize, Deserialize, Clone, JsonSchema)]
#[serde(rename_all = "snake_case", deny_unknown_fields, tag = "type")]
pub enum Config {
    V1(v1::Config),
}

/// The unlock configuration as stored in the public database. The variant records
/// which token derivation scheme the stored factor state and database key were
/// produced with, so that a server with a newer scheme can unlock with the old
/// scheme and then re-key.
#[derive(Serialize, Deserialize, Clone, JsonSchema)]
#[serde(rename_all = "snake_case", deny_unknown_fields, tag = "type")]
pub enum UnlockConfig {
    /// Legacy scheme: password and recovery phrase tokens are the raw entered bytes,
    /// `and` tokens are the plain concatenation of child tokens, and the database key
    /// is the zbase32 root token used as an sqlcipher passphrase.
    V1(v1::UnlockFactorsConfig),
    /// Current scheme: password and recovery phrase tokens are derived with argon2id
    /// and a stored per-factor salt, `and` tokens are a hash of length-prefixed child
    /// tokens, and the database key is the 32 byte root token used as a raw sqlcipher
    /// key.
    V2(v1::UnlockFactorsConfig),
}

impl GoodOrmningCustomString<UnlockConfig> for UnlockConfig {
    fn from_sql(value: String) -> Result<Self, String> {
        return serde_json::from_str(&value).map_err(|e| e.to_string());
    }

    fn to_sql<'a>(value: &'a Self) -> String {
        return serde_json::to_string(&value).unwrap();
    }
}
