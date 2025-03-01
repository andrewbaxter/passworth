use {
    gloo::utils::{
        format::JsValueSerdeExt,
        window,
    },
    http::Uri,
    js_sys::{
        Array,
        Promise,
    },
    passworth::{
        datapath::SpecificPath,
        ipc,
        utils::dig,
    },
    passworth_wasm::{
        browser,
        force_string,
        js_call,
        js_call2,
        js_get,
        ToContent,
    },
    rooting::{
        el,
        set_root,
        El,
        WeakEl,
    },
    serde::Serialize,
    serde_json::json,
    std::{
        future::Future,
        str::FromStr,
    },
    wasm_bindgen::{
        JsCast,
        JsValue,
    },
    wasm_bindgen_futures::{
        spawn_local,
        JsFuture,
    },
    web_sys::{
        console,
        HtmlInputElement,
    },
};

const ICON_CLOCK: &str = "clock";
const ICON_FIELD: &str = "field";
const ICON_PERSON: &str = "person";

fn el_block_err(text: impl AsRef<str>) -> El {
    return el("div").classes(&["err"]).text(text.as_ref());
}

fn el_async(work: impl Future<Output = Result<El, String>> + 'static) -> El {
    return el("div").classes(&["g_async"]).own(move |el_| {
        let el_ = el_.weak();
        spawn_local(async move {
            let work = work.await;
            let Some(el_) = el_.upgrade() else {
                return;
            };
            match work {
                Ok(r) => el_.ref_replace(vec![r]),
                Err(e) => el_.ref_replace(vec![el_block_err(e)]),
            }
        });
    });
}

fn el_vbox() -> El {
    return el("div").classes(&["g_vbox"]);
}

fn el_hbox() -> El {
    return el("div").classes(&["g_hbox"]);
}

fn el_group() -> El {
    return el("div").classes(&["g_group"]);
}

fn el_icon_button<
    Ft: 'static + Future<Output = Result<(), String>>,
    F: 'static + Fn() -> Ft,
>(icon: &str, help: &str, action: F) -> El {
    let out = el("button");
    out.ref_classes(&["g_icon_button"]);
    out.ref_attr("title", help);
    out.ref_text(icon);
    out.ref_on("click", {
        let out = out.weak();
        move |_| {
            let Some(out) = out.upgrade() else {
                return;
            };
            out.ref_classes(&["g_async"]);
            spawn_local({
                let out = out.weak();
                let action = action();
                async move {
                    if let Err(e) = action.await {
                        console::log_1(
                            &JsValue::from(format!("Async button invocation aborted with error: {}", e)),
                        );
                    }
                    let Some(out) = out.upgrade() else {
                        return;
                    };
                    out.ref_remove_classes(&["g_async"]);
                }
            });
        }
    });
    return out;
}

async fn send_to_native<T: ipc::msg::ReqTrait>(message: T) -> Result<T::Resp, String> {
    let arg1 = JsValue::from("me.isandrew.passworth");
    console::log_2(&JsValue::from("send_to_native0"), &arg1);
    let message = message.to_enum();
    let arg2 = JsValue::from_serde(&message).unwrap();
    console::log_2(&JsValue::from("send_to_native0 arg2"), &arg2);
    let call_res =
        js_call2(&js_get(&browser(), "runtime"), "sendNativeMessage", &arg1, &arg2).dyn_into::<Promise>().unwrap();
    console::log_2(&JsValue::from("send_to_native1 call res"), &call_res);
    let call_res = JsFuture::from(call_res).await.unwrap();
    console::log_2(&JsValue::from("send_to_native1 call res2"), &call_res);
    let x = JsValue::into_serde::<glove::Resp<T::Resp>>(&call_res).unwrap();
    console::log_1(&JsValue::from(format!("Got native response: {}", serde_json::to_string_pretty(&x).unwrap())));
    match x {
        glove::Resp::Ok(v) => return Ok(v),
        glove::Resp::Err(v) => return Err(
            format!(
                "Error making request to native messaging host [{}]: {}",
                serde_json::to_string(&message).unwrap(),
                v
            ),
        ),
    }
}

async fn get_active_tab() -> (JsValue, JsValue) {
    console::log_1(&JsValue::from("z0"));
    let browser = browser();
    console::log_1(&JsValue::from("z0b"));
    let tabs = js_get(&browser, "tabs");
    console::log_1(&JsValue::from("z1"));
    let query_res = JsFuture::from(js_call(&tabs, "query", &JsValue::from_serde(&json!({
        "currentWindow": true,
        "active": true,
    })).unwrap()).dyn_into::<Promise>().unwrap()).await.unwrap();
    console::log_1(&JsValue::from("z2"));
    for tab in query_res.dyn_into::<Array>().unwrap() {
        return (tabs, tab);
    }
    console::log_1(&JsValue::from("z3"));
    panic!("Couldn't find active tab");
}

async fn send_to_content(message: impl Serialize) {
    let (tabs, tab) = get_active_tab().await;
    js_call2(
        &tabs,
        "sendMessage",
        &js_sys::Reflect::get(&tab, &JsValue::from("id")).unwrap(),
        &JsValue::from_serde(&message).unwrap(),
    );
}

fn update(tree_root: &El, raw_paths: Vec<String>) {
    let mut paths = vec![];
    for raw_path in raw_paths {
        let Ok(path) = SpecificPath::from_str(&raw_path) else {
            continue;
        };
        paths.push(path);
    }
    if paths.is_empty() {
        return;
    }
    tree_root.ref_clear();
    tree_root.ref_push(el_async(async move {
        console::log_1(&JsValue::from("TT0"));
        let raw_tree = send_to_native(ipc::ReqMetaKeys {
            paths: paths,
            at: None,
        }).await?;
        console::log_1(&JsValue::from("TT1"));
        let new_tree = el_vbox();

        fn build_row(path: SpecificPath, actions: Vec<El>) -> El {
            return el("div")
                .classes(&["s_tree_row"])
                .push(el("span").text(&path.to_string()))
                .push(el_hbox().extend(actions));
        }

        fn build_leaf(path: SpecificPath) -> El {
            let mut actions = vec![el_icon_button(ICON_FIELD, "Put value in text field", {
                let path = path.clone();
                move || {
                    let path = path.clone();
                    async move {
                        let resp = send_to_native(ipc::ReqRead {
                            paths: vec![path],
                            at: None,
                        }).await?;
                        send_to_content(ToContent::FillField(force_string(&resp))).await;
                        window().close().unwrap();
                        return Ok(());
                    }
                }
            })];
            if let Some(last) = path.0.last() {
                if last == "otp" {
                    actions.push(el_icon_button(ICON_CLOCK, "Put fresh OTP token in text field", {
                        let path = path.clone();
                        move || {
                            let path = path.clone();
                            async move {
                                let resp = send_to_native(ipc::ReqDeriveOtp { key: path }).await?;
                                send_to_content(ToContent::FillField(resp)).await;
                                window().close().unwrap();
                                return Ok(());
                            }
                        }
                    }));
                }
            }
            return build_row(path, actions);
        }

        fn build_group(path: SpecificPath, user_field: bool) -> El {
            return build_row(path.clone(), vec![el_icon_button(ICON_PERSON, "Auto-fill user and password", {
                move || {
                    let path = path.clone();
                    async move {
                        let password_path = path.child("password");
                        let mut req_paths = vec![password_path.clone()];
                        let user_path = path.child("user");
                        if user_field {
                            req_paths.push(user_path.clone());
                        }
                        let resp = send_to_native(ipc::ReqRead {
                            paths: req_paths,
                            at: None,
                        }).await?;
                        let user;
                        if user_field {
                            user = dig(&resp, user_path.0.iter()).unwrap().clone();
                        } else {
                            user = serde_json::Value::String(path.0.last().unwrap().clone());
                        }
                        send_to_content(
                            ToContent::FillUserPassword(
                                force_string(&user),
                                force_string(dig(&resp, password_path.0.iter()).unwrap()),
                            ),
                        ).await;
                        window().close().unwrap();
                        return Ok(());
                    }
                }
            })]);
        }

        match raw_tree {
            serde_json::Value::Object(map) => {
                fn recurse(out: &El, at: serde_json::Map<String, serde_json::Value>, path: &mut Vec<String>) {
                    if at.contains_key("password") {
                        out.ref_push(build_group(SpecificPath(path.clone()), at.contains_key("user")));
                    }
                    for (k, v) in at {
                        path.push(k);
                        if let serde_json::Value::Object(at2) = v {
                            recurse(out, at2, path);
                        } else {
                            out.ref_push(build_leaf(SpecificPath(path.clone())));
                        }
                        path.pop();
                    }
                }

                recurse(&new_tree, map, &mut vec![]);
            },
            serde_json::Value::Null => {
                new_tree.ref_push(el_block_err("No results"));
            },
            _ => {
                new_tree.ref_push(build_leaf(SpecificPath(vec![])));
            },
        }
        return Ok(new_tree);
    }));
}

fn main() {
    console_error_panic_hook::set_once();
    console::log_1(&JsValue::from("b1"));
    let tree_root = el_group();
    console::log_1(&JsValue::from("b2"));
    let addr = el("input");
    console::log_1(&JsValue::from("b3"));
    tree_root.ref_push(el_async({
        let addr = addr.weak();
        let tree_root = tree_root.weak();
        async move {
            console::log_1(&JsValue::from("b4"));
            let active_tab = get_active_tab().await.1;
            console::log_1(&JsValue::from("b4b"));
            let mut raw_paths = vec![];
            let url = js_sys::Reflect::get(&active_tab, &JsValue::from("url")).unwrap().as_string().unwrap();
            let url = Uri::from_str(&url).map_err(|e| format!("Unparsable URL: {}", e))?;
            let Some(hostname) = url.host() else {
                return Ok(el("div"));
            };
            let hostname_segs = hostname.split('.').collect::<Vec<_>>();
            for i in 0 ..= hostname_segs.len() - 2 {
                raw_paths.push(
                    SpecificPath(
                        vec![
                            "web".to_string(),
                            hostname_segs[hostname_segs.len() - 2 - i .. hostname_segs.len()].join(".")
                        ],
                    ).to_string(),
                );
            }
            console::log_1(&JsValue::from("b5"));
            let Some(addr) = addr.upgrade() else {
                return Ok(el("div"));
            };
            addr.ref_attr("value", &raw_paths[0]);
            console::log_1(&JsValue::from("b5b"));
            let Some(tree_root) = tree_root.upgrade() else {
                return Ok(el("div"));
            };
            update(&tree_root, raw_paths);
            console::log_1(&JsValue::from("b5c"));
            return Ok(el("div"));
        }
    }));
    console::log_1(&JsValue::from("b6"));

    fn update_from_addr(addr: &WeakEl, tree_root: &WeakEl) {
        let Some(addr) = addr.upgrade() else {
            return;
        };
        let Some(tree_root) = tree_root.upgrade() else {
            return;
        };
        update(&tree_root, vec![addr.raw().dyn_ref::<HtmlInputElement>().unwrap().value()]);
    }

    addr.ref_on("keyup", {
        let addr = addr.weak();
        let tree_root = tree_root.weak();
        move |_| {
            update_from_addr(&addr, &tree_root);
        }
    });
    console::log_1(&JsValue::from("b7"));
    addr.ref_on("change", {
        let addr = addr.weak();
        let tree_root = tree_root.weak();
        move |_| {
            update_from_addr(&addr, &tree_root);
        }
    });
    console::log_1(&JsValue::from("b8"));
    set_root(vec![addr, tree_root]);
    console::log_1(&JsValue::from("b9"));
}
