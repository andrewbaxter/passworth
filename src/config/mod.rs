use good_ormning_runtime::sqlite::GoodOrmningCustomString;
use serde::{
    Deserialize,
    Serialize,
};

pub mod v1;

pub use v1 as latest;

#[derive(Serialize, Deserialize, Clone)]
#[serde(rename_all = "snake_case")]
pub enum Config {
    V1(v1::Config),
}

impl GoodOrmningCustomString<Config> for Config {
    fn to_sql<'a>(value: &'a Config) -> std::borrow::Cow<'a, str> {
        return serde_json::to_string(&value).unwrap().into();
    }

    fn from_sql(value: String) -> Result<Config, String> {
        return serde_json::from_str(&value).map_err(|e| e.to_string());
    }
}
