use {
    gloo::utils::window,
    js_sys::{
        Function,
        Promise,
    },
    serde::{
        Deserialize,
        Serialize,
    },
    wasm_bindgen::{
        prelude::wasm_bindgen,
        JsCast,
        JsValue,
    },
};

#[derive(Serialize, Deserialize)]
pub enum ToContent {
    FillUserPassword(String, String),
    FillField(String),
}

#[wasm_bindgen]
extern "C" {
    //. .
    #[wasm_bindgen(extends = ::js_sys::Object, js_name = Tabs, typescript_type = "Tabs")]
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub type Tabs;
    #[wasm_bindgen(structural, method, js_class = "Tabs", js_name = sendMessage)]
    pub fn send_message(this: &Tabs, tab_id: &JsValue, data: &JsValue);
    #[wasm_bindgen(structural, method, js_class = "Tabs", js_name = query)]
    pub fn query(this: &Tabs, data: &JsValue) -> Promise;

    //. .
    #[wasm_bindgen(extends = ::js_sys::Object, js_name = Runtime, typescript_type = "OnMessage")]
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub type OnMessage;
    #[wasm_bindgen(structural, method, getter, js_class = "OnMessage", js_name = addListener)]
    pub fn add_listener(this: &OnMessage, listener: &Function) -> OnMessage;

    //. .
    #[wasm_bindgen(extends = ::js_sys::Object, js_name = Runtime, typescript_type = "Runtime")]
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub type Runtime;
    #[wasm_bindgen(structural, method, getter, js_class = "Runtime", js_name = onMessage)]
    pub fn on_message(this: &Runtime) -> OnMessage;
    #[wasm_bindgen(structural, method, getter, js_class = "Runtime", js_name = sendNativeMessage)]
    pub fn send_native_message(this: &Runtime, application: &str, message: &JsValue) -> Promise;

    //. .
    #[wasm_bindgen(extends = ::js_sys::Object, js_name = Browser, typescript_type = "Browser")]
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub type Browser;
    #[wasm_bindgen(structural, method, getter, js_class = "Browser", js_name = tabs)]
    pub fn tabs(this: &Browser) -> Tabs;
    #[wasm_bindgen(structural, method, getter, js_class = "Browser", js_name = tabs)]
    pub fn runtime(this: &Browser) -> Runtime;
}

pub fn browser() -> Browser {
    return window().get("browser").unwrap().dyn_into::<Browser>().unwrap();
}

pub fn force_string(v: &serde_json::Value) -> String {
    if let serde_json::Value::String(v) = v {
        return v.clone();
    } else {
        return serde_json::to_string(&v).unwrap();
    };
}
