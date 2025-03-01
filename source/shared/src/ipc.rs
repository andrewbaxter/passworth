use {
    crate::datapath::SpecificPath,
    glove::reqresp,
    schemars::JsonSchema,
    serde::{
        Deserialize,
        Serialize,
    },
};

#[derive(Serialize, Deserialize, Clone, JsonSchema)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct C2SGenerateVariantBytes {
    pub length: usize,
}

#[derive(Serialize, Deserialize, Clone, JsonSchema)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct C2SGenerateVariantSafeAlphanumeric {
    pub length: usize,
}

#[derive(Serialize, Deserialize, Clone, JsonSchema)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct C2SGenerateVariantAlphanumeric {
    pub length: usize,
}

#[derive(Serialize, Deserialize, Clone, JsonSchema)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct C2SGenerateVariantAlphanumericSymbols {
    pub length: usize,
}

#[derive(Serialize, Deserialize, Clone, JsonSchema)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum C2SGenerateVariant {
    Bytes(C2SGenerateVariantBytes),
    SafeAlphanumeric(C2SGenerateVariantSafeAlphanumeric),
    Alphanumeric(C2SGenerateVariantAlphanumeric),
    AlphanumericSymbols(C2SGenerateVariantAlphanumericSymbols),
    Pgp,
    Ssh,
}
#[derive(Serialize, Deserialize, Clone, JsonSchema)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct ReqUnlock;

#[derive(Serialize, Deserialize, Clone, JsonSchema)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum LockAction {
    Lock,
    Unlock,
}

#[derive(Serialize, Deserialize, Clone, JsonSchema)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct ReqLock(pub LockAction);

#[derive(Serialize, Deserialize, Clone, JsonSchema)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct ReqRead {
    pub paths: Vec<SpecificPath>,
    pub at: Option<i64>,
}

#[derive(Serialize, Deserialize, Clone, JsonSchema)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct ReqMetaKeys {
    pub paths: Vec<SpecificPath>,
    pub at: Option<i64>,
}

#[derive(Serialize, Deserialize, Clone, JsonSchema)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct ReqMetaRevisions {
    pub paths: Vec<SpecificPath>,
    pub at: Option<i64>,
}

#[derive(Serialize, Deserialize, Clone, JsonSchema)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct ReqMetaPgpPubkey {
    pub path: SpecificPath,
    pub at: Option<i64>,
}

#[derive(Serialize, Deserialize, Clone, JsonSchema)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct ReqMetaSshPubkey {
    pub path: SpecificPath,
    pub at: Option<i64>,
}

#[derive(Serialize, Deserialize, Clone, JsonSchema)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct ReqWrite(pub Vec<(SpecificPath, serde_json::Value)>);

#[derive(Serialize, Deserialize, Clone, JsonSchema)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct ReqWriteMove {
    pub from: SpecificPath,
    pub to: SpecificPath,
    pub overwrite: bool,
}

#[derive(Serialize, Deserialize, Clone, JsonSchema)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct ReqWriteGenerate {
    pub path: SpecificPath,
    pub variant: C2SGenerateVariant,
    pub overwrite: bool,
}

#[derive(Serialize, Deserialize, Clone, JsonSchema)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct ReqWriteRevert {
    pub paths: Vec<SpecificPath>,
    pub at: i64,
}

#[derive(Serialize, Deserialize, Clone, JsonSchema)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct ReqDerivePgpSign {
    pub key: SpecificPath,
    pub data: Vec<u8>,
}

#[derive(Serialize, Deserialize, Clone, JsonSchema)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct ReqDerivePgpDecrypt {
    pub key: SpecificPath,
    pub data: Vec<u8>,
}

#[derive(Serialize, Deserialize, Clone, JsonSchema)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct ReqDeriveOtp {
    pub key: SpecificPath,
}

reqresp!(pub msg {
    Lock(ReqLock) =>(),
    MetaKeys(ReqMetaKeys) => serde_json:: Value,
    MetaRevisions(ReqMetaRevisions) => serde_json:: Value,
    MetaPgpPubkey(ReqMetaPgpPubkey) => String,
    MetaSshPubkey(ReqMetaSshPubkey) => String,
    Read(ReqRead) => serde_json:: Value,
    Write(ReqWrite) =>(),
    WriteMove(ReqWriteMove) =>(),
    WriteGenerate(ReqWriteGenerate) =>(),
    WriteRevert(ReqWriteRevert) =>(),
    DerivePgpSign(ReqDerivePgpSign) => String,
    DerivePgpDecrypt(ReqDerivePgpDecrypt) => Vec < u8 >,
    DeriveOtp(ReqDeriveOtp) => String,
});
