use {
    gloo::{
        events::{
            EventListener,
            EventListenerOptions,
        },
        storage::{
            LocalStorage,
            Storage,
        },
        utils::{
            format::JsValueSerdeExt,
            window,
        },
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
        ToContentField,
        ToContentUserPassword,
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
        cell::RefCell,
        future::Future,
        rc::Rc,
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
        HtmlElement,
        HtmlInputElement,
        KeyboardEvent,
    },
};

const ICON_CLOCK: &str = "&#xe8b5";
const ICON_FIELD: &str = "&#xf51d";
const ICON_PERSON: &str = "&#xe7fd";
const CLASS_VBOX: &str = "g_vbox";
const CLASS_HBOX: &str = "g_hbox";
const CLASS_GROUP: &str = "g_group";
const CLASS_ASYNC: &str = "g_async";
const CLASS_ERROR: &str = "g_err";
const CLASS_ACTION_FOCUS: &str = "s_action_focus";

fn el_block_err(text: impl AsRef<str>) -> El {
    return el("div").classes(&[CLASS_ERROR]).text(text.as_ref());
}

fn el_block_text(text: impl AsRef<str>) -> El {
    return el("p").text(text.as_ref());
}

fn el_async(work: impl Future<Output = Result<El, String>> + 'static) -> El {
    return el("div").classes(&[CLASS_ASYNC]).own(move |el_| {
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
    return el("div").classes(&[CLASS_VBOX]);
}

fn el_hbox() -> El {
    return el("div").classes(&[CLASS_HBOX]);
}

fn el_group() -> El {
    return el("div").classes(&[CLASS_GROUP]);
}

struct State {
    origin: RefCell<Option<String>>,
    search_path: RefCell<Option<SpecificPath>>,
    focus: RefCell<Option<El>>,
}

fn save_search_path(state: &Rc<State>) {
    let Some(origin) = &*state.origin.borrow() else {
        return;
    };
    let Some(search_path) = &*state.search_path.borrow() else {
        return;
    };
    if let Err(e) = LocalStorage::set(&origin, &search_path.to_string()) {
        console::log_1(
            &JsValue::from(
                format!("Error saving search path [{}] for origin [{}]: {}", search_path.to_string(), origin, e),
            ),
        );
    }
}

fn el_choice_button<
    Ft: 'static + Future<Output = Result<(), String>>,
    F: 'static + Fn() -> Ft,
>(state: &Rc<State>, icon: &str, help: &str, action: F) -> El {
    let out = el("button");
    out.ref_classes(&["g_icon_button", "s_choice_button"]);
    out.ref_attr("title", help);
    out.raw().set_inner_html(icon);
    out.ref_on("click", {
        let out = out.weak();
        move |_| {
            let Some(out) = out.upgrade() else {
                return;
            };
            out.ref_classes(&[CLASS_ASYNC]);
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
                    out.ref_remove_classes(&[CLASS_ASYNC]);
                }
            });
        }
    });
    out.ref_own(
        |button| EventListener::new_with_options(&window(), "focus", EventListenerOptions::run_in_capture_phase(), {
            let button = button.weak();
            let state = state.clone();
            move |_| {
                let Some(button) = button.upgrade() else {
                    return;
                };
                if let Some(focus) = state.focus.borrow_mut().take() {
                    focus.ref_remove_classes(&[CLASS_ACTION_FOCUS]);
                }
                button.ref_classes(&[CLASS_ACTION_FOCUS]);
                *state.focus.borrow_mut() = Some(button);
            }
        }),
    );
    if state.focus.borrow().is_none() {
        *state.focus.borrow_mut() = Some(out.clone());
        out.ref_classes(&[CLASS_ACTION_FOCUS]);
    }
    return out;
}

async fn send_to_native<T: ipc::msg::ReqTrait>(message: T) -> Result<T::Resp, String> {
    let message = message.to_enum();
    match JsValue::into_serde::<glove::Resp<T::Resp>>(
        &JsFuture::from(
            js_call2(
                &js_get(&browser(), "runtime"),
                "sendNativeMessage",
                &JsValue::from("me.isandrew.passworth"),
                &JsValue::from_serde(&message).unwrap(),
            )
                .dyn_into::<Promise>()
                .unwrap(),
        )
            .await
            .unwrap(),
    ).unwrap() {
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
    let tabs = js_get(&browser(), "tabs");
    for tab in JsFuture::from(js_call(&tabs, "query", &JsValue::from_serde(&json!({
        "currentWindow": true,
        "active": true,
    })).unwrap()).dyn_into::<Promise>().unwrap()).await.unwrap().dyn_into::<Array>().unwrap() {
        return (tabs, tab);
    }
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

fn update(state: &Rc<State>, tree_root: &El, raw_path: String) {
    let Ok(path) = SpecificPath::from_str(&raw_path) else {
        return;
    };
    *state.search_path.borrow_mut() = Some(path.clone());
    *state.focus.borrow_mut() = None;
    tree_root.ref_clear();
    tree_root.ref_push(el_async({
        let state = state.clone();
        async move {
            let mut raw_tree = send_to_native(ipc::ReqMetaKeys {
                paths: vec![path.clone()],
                at: None,
            }).await?;
            for seg in &path.0 {
                let serde_json::Value::Object(mut t) = raw_tree else {
                    return Err(format!("Response missing path prefix"));
                };
                let Some(t) = t.remove(seg) else {
                    return Err(format!("Response missing path prefix"));
                };
                raw_tree = t;
            }
            let new_tree = el_vbox().classes(&["s_choices"]);

            fn build_row(path: SpecificPath, actions: Vec<El>) -> El {
                let mut head = path.0.clone();
                head.pop();
                let head = SpecificPath(head).to_string();
                let tail = SpecificPath(path.0.last().iter().map(|x| x.to_string()).collect()).to_string();
                let mut head = head.as_str();
                let mut tail = tail.as_str();
                if head.is_empty() {
                    tail = tail.strip_prefix("/").unwrap_or(tail);
                } else {
                    head = head.strip_prefix("/").unwrap_or(head);
                }
                return el("div")
                    .classes(&["s_choice"])
                    .push(
                        el_hbox()
                            .classes(&["s_choice_label"])
                            .push(el("span").classes(&["s_choice_label_head"]).text(head))
                            .push(el("span").classes(&["s_choice_label_tail"]).text(tail)),
                    )
                    .push(el_hbox().classes(&["s_choice_buttons"]).extend(actions));
            }

            fn build_leaf(state: &Rc<State>, path: SpecificPath) -> El {
                let mut actions = vec![el_choice_button(state, ICON_FIELD, "Put value in text field", {
                    let path = path.clone();
                    let state = state.clone();
                    move || {
                        let path = path.clone();
                        let state = state.clone();
                        async move {
                            save_search_path(&state);
                            let resp = send_to_native(ipc::ReqRead {
                                paths: vec![path],
                                at: None,
                            }).await?;
                            send_to_content(
                                ToContent::FillField(ToContentField { text: force_string(&resp) }),
                            ).await;
                            window().close().unwrap();
                            return Ok(());
                        }
                    }
                })];
                if let Some(last) = path.0.last() {
                    if last == "otp" {
                        actions.push(el_choice_button(state, ICON_CLOCK, "Put fresh OTP token in text field", {
                            let path = path.clone();
                            let state = state.clone();
                            move || {
                                let path = path.clone();
                                let state = state.clone();
                                async move {
                                    save_search_path(&state);
                                    let resp = send_to_native(ipc::ReqDeriveOtp { key: path }).await?;
                                    send_to_content(ToContent::FillField(ToContentField { text: resp })).await;
                                    window().close().unwrap();
                                    return Ok(());
                                }
                            }
                        }));
                    }
                }
                return build_row(path, actions);
            }

            fn build_group(state: &Rc<State>, path: SpecificPath, user_field: bool) -> El {
                return build_row(
                    path.clone(),
                    vec![el_choice_button(state, ICON_PERSON, "Auto-fill user and password", {
                        let state = state.clone();
                        move || {
                            let state = state.clone();
                            let path = path.clone();
                            async move {
                                save_search_path(&state);
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
                                send_to_content(ToContent::FillUserPassword(ToContentUserPassword {
                                    user: force_string(&user),
                                    password: force_string(dig(&resp, password_path.0.iter()).unwrap()),
                                })).await;
                                window().close().unwrap();
                                return Ok(());
                            }
                        }
                    })],
                );
            }

            match raw_tree {
                serde_json::Value::Object(map) => {
                    fn recurse(
                        state: &Rc<State>,
                        out: &El,
                        at: serde_json::Map<String, serde_json::Value>,
                        path: &mut Vec<String>,
                    ) {
                        if at.contains_key("password") {
                            out.ref_push(build_group(state, SpecificPath(path.clone()), at.contains_key("user")));
                        }
                        for (k, v) in at {
                            path.push(k);
                            if let serde_json::Value::Object(at2) = v {
                                recurse(state, out, at2, path);
                            } else {
                                out.ref_push(build_leaf(state, SpecificPath(path.clone())));
                            }
                            path.pop();
                        }
                    }

                    recurse(&state, &new_tree, map, &mut vec![]);
                },
                serde_json::Value::Null => {
                    return Ok(el_block_text("No results"));
                },
                _ => {
                    return Err(format!("Response included non-null leaf values"));
                },
            }
            return Ok(new_tree);
        }
    }));
}

fn main() {
    console_error_panic_hook::set_once();
    let state = Rc::new(State {
        origin: RefCell::new(None),
        search_path: RefCell::new(None),
        focus: RefCell::new(None),
    });
    let tree_root =
        el_group().own(
            |_| EventListener::new_with_options(&window(), "keydown", EventListenerOptions::run_in_capture_phase(), {
                let state = state.clone();
                move |ev| {
                    let ev = ev.dyn_ref::<KeyboardEvent>().unwrap();
                    if ev.code().to_ascii_lowercase() != "enter" {
                        return;
                    }
                    let Some(focus) = state.focus.borrow_mut().clone() else {
                        return;
                    };
                    focus.raw().dyn_into::<HtmlElement>().unwrap().click();
                    ev.prevent_default();
                    ev.set_cancel_bubble(true);
                }
            }),
        );
    let addr = el("input").classes(&["s_location"]);
    tree_root.ref_push(el_async({
        let addr = addr.weak();
        let tree_root = tree_root.weak();
        let state = state.clone();
        async move {
            let active_tab = get_active_tab().await.1;
            let url = js_sys::Reflect::get(&active_tab, &JsValue::from("url")).unwrap().as_string().unwrap();
            let url = Uri::from_str(&url).map_err(|e| format!("Unparsable URL: {}", e))?;
            if let Some(authority) = url.authority() {
                *state.origin.borrow_mut() = Some(authority.to_string());
            }
            let Some(hostname) = url.host() else {
                return Ok(el("div"));
            };
            let hostname_segs = hostname.split('.').collect::<Vec<_>>();
            let raw_path =
                SpecificPath(
                    vec!["web".to_string(), hostname_segs[hostname_segs.len() - 2 .. hostname_segs.len()].join(".")],
                ).to_string();
            let Some(addr) = addr.upgrade() else {
                return Ok(el("div"));
            };
            addr.ref_attr("value", &raw_path);
            let Some(tree_root) = tree_root.upgrade() else {
                return Ok(el("div"));
            };
            update(&state, &tree_root, raw_path);
            return Ok(el("div"));
        }
    }));

    fn update_from_addr(state: &Rc<State>, addr: &WeakEl, tree_root: &WeakEl) {
        let Some(addr) = addr.upgrade() else {
            return;
        };
        let Some(tree_root) = tree_root.upgrade() else {
            return;
        };
        let addr = addr.raw().dyn_into::<HtmlInputElement>().unwrap();
        update(&state, &tree_root, addr.value());
    }

    addr.ref_on("keyup", {
        let addr = addr.weak();
        let tree_root = tree_root.weak();
        let state = state.clone();
        move |_| {
            update_from_addr(&state, &addr, &tree_root);
        }
    });
    addr.ref_on("change", {
        let addr = addr.weak();
        let tree_root = tree_root.weak();
        let state = state.clone();
        move |_| {
            update_from_addr(&state, &addr, &tree_root);
        }
    });
    set_root(vec![addr, tree_root]);
}
