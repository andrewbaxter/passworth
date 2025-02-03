use {
    good_ormning_runtime::sqlite::GoodOrmningCustomString,
    schemars::JsonSchema,
    serde::{
        Deserialize,
        Serialize,
    },
    std::path::PathBuf,
};

#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, JsonSchema)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct ConfigCredSmartcard {
    pub fingerprint: String,
    /// If pinentry, this must be null and will use the entered pin.  If not pinentry,
    /// either uses the config-specified pin or no pin.
    #[serde(default)]
    pub pin: Option<String>,
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, JsonSchema)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct ConfigCredSmartcards {
    /// If true, use the pin preconfigured for each smartcard instead of showing
    /// pinentry.
    #[serde(default)]
    pub fixed_pin: bool,
    /// List of cards that can be used.
    pub smartcards: Vec<ConfigCredSmartcard>,
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, JsonSchema)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum ConfigAuthFactorVariant {
    And(Vec<String>),
    Or(Vec<String>),
    Password,
    Smartcards(ConfigCredSmartcards),
    RecoveryCode,
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, JsonSchema)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct ConfigAuthFactor {
    pub id: String,
    pub description: String,
    pub variant: ConfigAuthFactorVariant,
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, JsonSchema)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct ConfigAuthMethod {
    pub description: String,
    pub root_factor: String,
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, JsonSchema)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct ConfigPrompt {
    pub description: String,
    #[serde(default)]
    pub remember_seconds: u64,
}

#[derive(Serialize, Deserialize, Clone, JsonSchema)]
#[serde(untagged)]
pub enum UserGroupId {
    Name(String),
    Id(u32),
}

#[derive(Serialize, Deserialize, Clone, JsonSchema)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct MatchUser {
    #[serde(default)]
    pub user: Option<UserGroupId>,
    #[serde(default)]
    pub group: Option<UserGroupId>,
    #[serde(default)]
    pub walk_ancestors: bool,
}

#[derive(Serialize, Deserialize, Clone, JsonSchema)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct MatchBinary {
    pub path: PathBuf,
    #[serde(default)]
    pub walk_ancestors: bool,
}

#[derive(Serialize, Deserialize, Clone, JsonSchema)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct ConfigPermissionRule {
    /// Paths to which this rule applies. To apply to everything, use the empty path
    /// `""`. In the format `/seg/seg/.../seg` - no initial slash. Segments are
    /// literals or `*`, and `*` and `/` can be escaped with a backslash. `*` is a
    /// wildcard, and must appear as a whole segment.
    pub paths: Vec<String>,
    /// Match requesting processes against a systemd service name (via service pid).
    #[serde(default)]
    pub match_systemd: Option<String>,
    /// Match requesting processes against the process or a parent process owner.
    #[serde(default)]
    pub match_user: Option<MatchUser>,
    /// Match requesting processes against the process or a parent process binary path.
    /// This only applies to binaries available in the root filesystem namespace.
    #[serde(default)]
    pub match_binary: Option<MatchBinary>,
    /// Permission to explicitly lock or unlock.
    #[serde(default)]
    pub permit_lock: bool,
    /// Permission to lock/unlock and indirectly access data via derivation - totp,
    /// asymmetric signatures, decryption
    #[serde(default)]
    pub permit_derive: bool,
    /// Lock/unlock or read the credential data itself
    #[serde(default)]
    pub permit_read: bool,
    /// Lock/unlock, write or read the credential data itself.
    #[serde(default)]
    pub permit_write: bool,
    /// Configure if access requires prompting.
    #[serde(default)]
    pub prompt: Option<ConfigPrompt>,
}

#[derive(Serialize, Deserialize, Clone, JsonSchema)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct Config {
    #[serde(rename = "$schema", skip_serializing)]
    pub _schema: Option<String>,
    /// A directory where this will store sqlite databases.
    pub data_path: PathBuf,
    /// Lock if no successful activity for this many seconds.
    pub lock_timeout: u64,
    /// How to unlock the database when credentials are accessed. These form a tree via
    /// references.
    pub auth_factors: Vec<ConfigAuthFactor>,
    /// Which factor forms the root of the tree (provides the database key).
    pub root_factor: String,
    /// Permissions for processes to access subtrees.
    pub access: Vec<ConfigPermissionRule>,
}

impl GoodOrmningCustomString<Config> for Config {
    fn to_sql<'a>(value: &'a Config) -> String {
        return serde_json::to_string(&value).unwrap().into();
    }

    fn from_sql(value: String) -> Result<Config, String> {
        return serde_json::from_str(&value).map_err(|e| e.to_string());
    }
}
