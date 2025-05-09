use {
    flowcontrol::{
        exenum,
        shed,
    },
    gloo::{
        events::{
            EventListener,
            EventListenerOptions,
        },
        storage::{
            LocalStorage,
            Storage,
        },
        timers::callback::Timeout,
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
    },
    serde::{
        Deserialize,
        Serialize,
    },
    serde_json::json,
    std::{
        cell::RefCell,
        collections::HashMap,
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
    search_path: RefCell<Option<String>>,
    focus: RefCell<Option<El>>,
}

fn storage_site_key(origin: &str) -> String {
    return format!("site_{}", origin);
}

const STORAGE_PSL_KEY: &str = "psl";

#[derive(Serialize, Deserialize)]
enum PslEntry {
    Branch(HashMap<String, PslEntry>),
    Leaf,
}

type Psl = HashMap<String, PslEntry>;

fn save_search_path(state: &Rc<State>) {
    let Some(origin) = &*state.origin.borrow() else {
        return;
    };
    let Some(search_path) = &*state.search_path.borrow() else {
        return;
    };
    if let Err(e) = LocalStorage::set(&storage_site_key(origin), search_path) {
        console::log_1(
            &JsValue::from(format!("Error saving search path [{}] for origin [{}]: {}", search_path, origin, e)),
        );
    }
}

fn el_choice_button<
    Ft: 'static + Future<Output = Result<(), String>>,
    F: 'static + Fn() -> Ft,
>(state: &Rc<State>, messages_el: &El, icon: &str, help: &str, action: F) -> El {
    let button_el = el("button");
    button_el.ref_classes(&["g_icon_button", "s_choice_button"]);
    button_el.ref_attr("title", help);
    button_el.raw().set_inner_html(icon);
    button_el.ref_on("click", {
        let button_el = button_el.weak();
        let messages_el = messages_el.weak();
        move |_| {
            if let Some(button_el) = button_el.upgrade() {
                button_el.ref_classes(&[CLASS_ASYNC]);
            }
            spawn_local({
                let button_el = button_el.clone();
                let messages_el = messages_el.clone();
                let action = action();
                async move {
                    let res = action.await;
                    let Some(button_el) = button_el.upgrade() else {
                        return;
                    };
                    let Some(messages_el) = messages_el.upgrade() else {
                        return;
                    };
                    button_el.ref_remove_classes(&[CLASS_ASYNC]);
                    messages_el.ref_clear();
                    if let Err(e) = res {
                        messages_el.ref_push(el_block_err(e));
                    }
                }
            });
        }
    });
    button_el.ref_own(
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
        *state.focus.borrow_mut() = Some(button_el.clone());
        button_el.ref_classes(&[CLASS_ACTION_FOCUS]);
    }
    return button_el;
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

async fn send_to_content(message: impl Serialize) -> Result<(), String> {
    let (tabs, tab) = get_active_tab().await;
    let res =
        JsFuture::from(
            js_call2(
                &tabs,
                "sendMessage",
                &js_sys::Reflect::get(&tab, &JsValue::from("id")).unwrap(),
                &JsValue::from_serde(&message).unwrap(),
            )
                .dyn_into::<Promise>()
                .unwrap(),
        )
            .await
            .unwrap();
    if res.is_null() {
        return Ok(());
    }
    return Err(res.as_string().unwrap());
}

fn update(state: &Rc<State>, tree_root_el: &El, messages_el: &El, raw_path: String) {
    let Ok(mut path) = SpecificPath::from_str(&raw_path) else {
        return;
    };
    let parent;
    let prefix;
    if path.0.is_empty() {
        prefix = "".to_string();
        parent = path.clone();
    } else {
        prefix = path.0.pop().unwrap();
        parent = path.clone();
    }
    *state.search_path.borrow_mut() = Some(raw_path);
    *state.focus.borrow_mut() = None;
    tree_root_el.ref_clear();
    tree_root_el.ref_push(el_async({
        let state = state.clone();
        let messages_el = messages_el.weak();
        async move {
            // Async
            let raw_tree = send_to_native(ipc::ReqMetaKeys {
                paths: vec![parent.clone()],
                at: None,
            }).await?;

            // Sync
            let Some(messages_el) = messages_el.upgrade() else {
                return Ok(el("div"));
            };

            fn build_row(subpath: &Vec<String>, actions: Vec<El>) -> El {
                let mut head = subpath.clone();
                head.pop();
                let head = SpecificPath(head).to_string();
                let tail = SpecificPath(subpath.last().iter().map(|x| x.to_string()).collect()).to_string();
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

            fn build_leaf(state: &Rc<State>, messages_el: &El, path: &SpecificPath, subpath: &Vec<String>) -> El {
                let mut actions = vec![el_choice_button(state, messages_el, ICON_FIELD, "Put value in text field", {
                    let path = path.clone();
                    let state = state.clone();
                    move || {
                        let path = path.clone();
                        let state = state.clone();
                        async move {
                            save_search_path(&state);
                            let resp = send_to_native(ipc::ReqRead {
                                paths: vec![path.clone()],
                                at: None,
                            }).await?;
                            send_to_content(ToContent::FillField(ToContentField { text: force_string(
                                //. .
                                dig(&resp, &path.0).ok_or_else(|| format!("Response missing expected data path ancestry"))?,
                            ) })).await?;
                            window().close().unwrap();
                            return Ok(());
                        }
                    }
                })];
                if let Some(last) = path.0.last() {
                    if last == "otp" {
                        actions.push(
                            el_choice_button(state, messages_el, ICON_CLOCK, "Put fresh OTP token in text field", {
                                let path = path.clone();
                                let state = state.clone();
                                move || {
                                    let path = path.clone();
                                    let state = state.clone();
                                    async move {
                                        save_search_path(&state);
                                        let resp = send_to_native(ipc::ReqDeriveOtp { key: path }).await?;
                                        send_to_content(ToContent::FillField(ToContentField { text: resp })).await?;
                                        window().close().unwrap();
                                        return Ok(());
                                    }
                                }
                            }),
                        );
                    }
                }
                return build_row(subpath, actions);
            }

            fn build_group(
                state: &Rc<State>,
                messages_el: &El,
                path: &SpecificPath,
                subpath: &Vec<String>,
                user_field: bool,
            ) -> El {
                return build_row(
                    subpath,
                    vec![el_choice_button(state, messages_el, ICON_PERSON, "Auto-fill user and password", {
                        let state = state.clone();
                        let path = path.clone();
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
                                    user = dig(&resp, &user_path.0).unwrap().clone();
                                } else {
                                    user = serde_json::Value::String(path.0.last().unwrap().clone());
                                }
                                send_to_content(ToContent::FillUserPassword(ToContentUserPassword {
                                    user: force_string(&user),
                                    password: force_string(dig(&resp, &password_path.0).unwrap()),
                                })).await?;
                                window().close().unwrap();
                                return Ok(());
                            }
                        }
                    })],
                );
            }

            let mut choices = vec![];
            if let serde_json::Value::Object(root) =
                dig(&raw_tree, &parent.0).ok_or_else(|| format!("Response missing path prefix"))? {
                let mut path = parent;
                let mut subpath = vec![];
                for (k, v) in root {
                    if !k.starts_with(&prefix) {
                        continue;
                    }
                    path.0.push(k.clone());
                    subpath.push(k.clone());

                    fn recurse(
                        state: &Rc<State>,
                        messages_el: &El,
                        out: &mut Vec<El>,
                        at: &serde_json::Value,
                        path: &mut SpecificPath,
                        subpath: &mut Vec<String>,
                    ) {
                        match at {
                            serde_json::Value::Object(at) => {
                                if at.contains_key("password") {
                                    out.push(
                                        build_group(state, messages_el, path, subpath, at.contains_key("user")),
                                    );
                                }
                                for (k, v) in at {
                                    path.0.push(k.clone());
                                    subpath.push(k.clone());
                                    recurse(state, messages_el, out, v, path, subpath);
                                    path.0.pop();
                                    subpath.pop();
                                }
                            },
                            _ => {
                                out.push(build_leaf(state, messages_el, path, subpath));
                            },
                        }
                    }

                    recurse(&state, &messages_el, &mut choices, v, &mut path, &mut subpath);
                    path.0.pop();
                    subpath.pop();
                }
            }
            if choices.is_empty() {
                return Ok(el_block_text("No results"));
            } else {
                return Ok(el_vbox().classes(&["s_choices"]).extend(choices));
            }
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
    let tree_root_el =
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
    let addr_el = el("input").classes(&["s_location"]);
    let messages_el = el_group();
    tree_root_el.ref_push(el_async({
        let addr_el = addr_el.weak();
        let messages_el = messages_el.weak();
        let tree_root_el = tree_root_el.weak();
        let state = state.clone();
        async move {
            let active_tab = get_active_tab().await.1;
            let url = js_sys::Reflect::get(&active_tab, &JsValue::from("url")).unwrap().as_string().unwrap();
            let url = Uri::from_str(&url).map_err(|e| format!("Unparsable URL: {}", e))?;
            let search_string;
            shed!{
                // Try saved search path
                if let Some(authority) = url.authority() {
                    let origin = authority.to_string();
                    *state.origin.borrow_mut() = Some(origin.clone());
                    if let Ok(search_string0) = LocalStorage::get(storage_site_key(&origin)) {
                        search_string = search_string0;
                        break;
                    }
                }

                // Get a reasonable search path from the current address host
                let Some(host) = url.host() else {
                    return Ok(el("div"));
                };
                let psl;
                if let Ok(psl0) = LocalStorage::get::<Psl>(STORAGE_PSL_KEY) {
                    psl = psl0;
                } else {
                    let mut psl0 = Psl::new();
                    for line in reqwest::get("https://publicsuffix.org/list/public_suffix_list.dat")
                        .await
                        .map_err(|e| format!("Error fetching public suffix list for domain splitting: {}", e))?
                        .text()
                        .await
                        .map_err(|e| format!("Error reading public suffix list data for domain splitting: {}", e))?
                        .lines() {
                        let line = line.trim();
                        if line.starts_with("//") {
                            continue;
                        }
                        if line.is_empty() {
                            continue;
                        }
                        let mut at = &mut psl0;
                        let mut rev_segs = line.split(".").collect::<Vec<_>>();
                        rev_segs.reverse();
                        let tail = rev_segs.pop().unwrap();
                        for seg in rev_segs {
                            if exenum!(at.get_mut(seg), Some(PslEntry::Branch(_)) =>()).is_none() {
                                at.insert(seg.to_string(), PslEntry::Branch(HashMap::new()));
                            }
                            at = exenum!(at.get_mut(seg), Some(PslEntry::Branch(p)) => p).unwrap();
                        }
                        at.entry(tail.to_string()).or_insert(PslEntry::Leaf);
                    }
                    LocalStorage::set(
                        STORAGE_PSL_KEY,
                        &psl0,
                    ).map_err(|e| format!("Couldn't put public storage list in local storage: {}", e))?;
                    psl = psl0;
                }
                let mut keep = vec![];
                let mut at_psl = Some(psl);
                for seg in host.split('.').rev() {
                    if let Some(next_psl) = at_psl.and_then(|mut p| p.remove(seg)) {
                        // Keep all psl segments
                        keep.push(seg);
                        at_psl = exenum!(next_psl, PslEntry:: Branch(p) => p);
                    } else {
                        // Keep 1 seg after psl
                        keep.push(seg);
                        break;
                    }
                }
                keep.reverse();
                search_string = SpecificPath(vec!["web".to_string(), keep.join(".")]).to_string();
            }

            // Set addr input
            let Some(addr) = addr_el.upgrade() else {
                return Ok(el("div"));
            };
            addr.ref_attr("value", &search_string);

            // Start querying + building tree
            let Some(tree_root_el) = tree_root_el.upgrade() else {
                return Ok(el("div"));
            };
            let Some(messages_el) = messages_el.upgrade() else {
                return Ok(el("div"));
            };
            update(&state, &tree_root_el, &messages_el, search_string);

            // Temporary placeholder
            return Ok(el("div"));
        }
    }));
    addr_el.ref_on("input", {
        let addr_el = addr_el.weak();
        let messages_el = messages_el.weak();
        let tree_root_el = tree_root_el.weak();
        let state = state.clone();

        // (hack: underscore makes various lints not apply (?) - they were wrong anyway,
        // and `allow(...)` wasn't entirely working, plus upstream bugs (expr vs
        // statement...))
        let mut _input_debounce = None;
        move |_| {
            _input_debounce = Some(Timeout::new(300, {
                let state = state.clone();
                let addr_el = addr_el.clone();
                let messages_el = messages_el.clone();
                let tree_root_el = tree_root_el.clone();
                move || {
                    let Some(addr_el) = addr_el.upgrade() else {
                        return;
                    };
                    let Some(messages_el) = messages_el.upgrade() else {
                        return;
                    };
                    let Some(tree_root_el) = tree_root_el.upgrade() else {
                        return;
                    };
                    update(
                        &state,
                        &tree_root_el,
                        &messages_el,
                        addr_el.raw().dyn_into::<HtmlInputElement>().unwrap().value(),
                    );
                }
            }));
        }
    });
    set_root(vec![el_vbox().classes(&["s_heading"]).push(addr_el).push(messages_el), tree_root_el]);
}
