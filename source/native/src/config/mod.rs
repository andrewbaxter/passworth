use {
    good_ormning_runtime::sqlite::GoodOrmningCustomString,
    schemars::JsonSchema,
    serde::{
        Deserialize,
        Serialize,
    },
};

pub mod v1;

pub use v1 as latest;

#[derive(Serialize, Deserialize, Clone, JsonSchema)]
#[serde(rename_all = "snake_case", deny_unknown_fields, tag = "type")]
pub enum Config {
    V1(v1::Config),
}

impl GoodOrmningCustomString<Config> for Config {
    fn to_sql<'a>(value: &'a Config) -> String {
        return serde_json::to_string(&value).unwrap();
    }

    fn from_sql(value: String) -> Result<Config, String> {
        return serde_json::from_str(&value).map_err(|e| e.to_string());
    }
}
