use std::path::PathBuf;
use good_ormning_runtime::sqlite::GoodOrmningCustomString;
use serde::{
    Deserialize,
    Serialize,
};

#[derive(Serialize, Deserialize, Clone)]
#[serde(rename_all = "snake_case")]
pub struct Config {
    pub data_path: PathBuf,
    pub creds: Vec<ConfigCred>,
    pub access: Vec<ConfigAccessRule>,
}

impl GoodOrmningCustomString<Config> for Config {
    fn to_sql<'a>(value: &'a Config) -> std::borrow::Cow<'a, str> {
        return serde_json::to_string(&value).unwrap().into();
    }

    fn from_sql(value: String) -> Result<Config, String> {
        return serde_json::from_str(&value).map_err(|e| e.to_string());
    }
}
