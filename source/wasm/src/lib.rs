use {
    gloo::utils::window,
    js_sys::{
        Function,
        Reflect,
    },
    serde::{
        Deserialize,
        Serialize,
    },
    wasm_bindgen::{
        JsCast,
        JsValue,
    },
};

pub fn browser() -> JsValue {
    return window().get("browser").unwrap().dyn_into::<JsValue>().unwrap();
}

pub fn force_string(v: &serde_json::Value) -> String {
    if let serde_json::Value::String(v) = v {
        return v.clone();
    } else {
        return serde_json::to_string(&v).unwrap();
    };
}

pub fn js_call(this: &JsValue, method: &str, arg: &JsValue) -> JsValue {
    return js_get(this, method).dyn_into::<Function>().unwrap().call1(this, arg).unwrap();
}

pub fn js_call2(this: &JsValue, method: &str, arg: &JsValue, arg2: &JsValue) -> JsValue {
    return js_get(this, method).dyn_into::<Function>().unwrap().call2(this, arg, arg2).unwrap();
}

pub fn js_get(this: &JsValue, prop: &str) -> JsValue {
    return Reflect::get(this, &JsValue::from(prop)).unwrap();
}

#[derive(Serialize, Deserialize, Clone)]
#[serde(rename_all = "snake_case", deny_unknown_fields, tag = "type")]
pub enum ToContent {
    FillField(ToContentField),
    FillUserPassword(ToContentUserPassword),
}

#[derive(Serialize, Deserialize, Clone)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct ToContentField {
    pub text: String,
}

#[derive(Serialize, Deserialize, Clone)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct ToContentUserPassword {
    pub password: String,
    pub user: String,
}
