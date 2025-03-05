pub fn to_b32(data: &[u8]) -> String {
    return zbase32::encode_full_bytes(data);
}

pub fn from_b32(data: &String) -> Result<Vec<u8>, String> {
    return Ok(
        zbase32::decode_full_bytes_str(
            data,
        ).map_err(|x| format!("Error decoding zbase32 encoded binary data: {}", x))?,
    );
}

pub fn dig<
    P: AsRef<str>,
>(data: &serde_json::Value, path: impl IntoIterator<Item = P>) -> Option<&serde_json::Value> {
    let mut at = data;
    for seg in path {
        match at {
            serde_json::Value::Object(map) => {
                let Some(v) = map.get(seg.as_ref()) else {
                    return None;
                };
                at = v;
            },
            _ => {
                return None;
            },
        }
    }
    return Some(at);
}
