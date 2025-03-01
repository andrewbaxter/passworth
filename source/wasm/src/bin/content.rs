use {
    flowcontrol::shed,
    gloo::{
        events::EventListener,
        utils::{
            format::JsValueSerdeExt,
            window,
        },
    },
    js_sys::{
        Array,
        Function,
    },
    passworth_wasm::{
        browser,
        ToContent,
    },
    rooting::{
        set_root_non_dom,
    },
    std::{
        cell::RefCell,
        collections::HashMap,
        rc::Rc,
    },
    wasm_bindgen::{
        prelude::Closure,
        JsCast,
        JsValue,
    },
    web_sys::{
        HtmlFormElement,
        HtmlInputElement,
    },
};

fn main() {
    let last_focus = Rc::new(RefCell::new(None));
    let focus_listener = EventListener::new(&window(), "focus", {
        let last_focus = last_focus.clone();
        move |ev| {
            let Ok(e) = ev.target().unwrap().dyn_into::<HtmlInputElement>() else {
                return;
            };
            *last_focus.borrow_mut() = Some(e);
        }
    });
    let message_listener = Closure::wrap(Box::new({
        let last_focus = last_focus.clone();
        move |message: JsValue, _, responder: Function| -> () {
            responder.call1(&responder, &JsValue::null()).unwrap();
            match message.into_serde::<ToContent>().unwrap() {
                ToContent::FillUserPassword(req_user, req_password) => {
                    const USER_SELS: &[&str] =
                        &[
                            "input[autocomplete=username i]",
                            "input[name=login i]",
                            "input[name=user i]",
                            "input[name=username i]",
                            "input[name=email i]",
                            "input[name=alias i]",
                            "input[id=login i]",
                            "input[id=user i]",
                            "input[id=username i]",
                            "input[id=email i]",
                            "input[id=alias i]",
                            "input[class=login i]",
                            "input[class=user i]",
                            "input[class=username i]",
                            "input[class=email i]",
                            "input[class=alias i]",
                            "input[name*=login i]",
                            "input[name*=user i]",
                            "input[name*=email i]",
                            "input[name*=alias i]",
                            "input[id*=login i]",
                            "input[id*=user i]",
                            "input[id*=email i]",
                            "input[id*=alias i]",
                            "input[class*=login i]",
                            "input[class*=user i]",
                            "input[class*=email i]",
                            "input[class*=alias i]",
                            "input[type=email i]",
                            "input[autocomplete=email i]",
                            "input[type=text i]",
                            "input[type=tel i]",
                        ];
                    const PASSWORD_SELS: &[&str] =
                        &["input[type=password i][autocomplete=current-password i]", "input[type=password i]"];
                    let doc = window().document().unwrap();
                    let user_input;
                    let password_input;
                    shed!{
                        'found_inputs _;
                        struct FoundForm {
                            form: HtmlFormElement,
                            searched_for_user: bool,
                            user: Option<HtmlInputElement>,
                            password: Option<HtmlInputElement>,
                        }
                        let selected_form;
                        shed!{
                            'selected_form _;
                            #[derive(PartialEq, Eq, Hash)]
                            struct HasMark(bool);
                            #[derive(PartialEq, Eq, Hash)]
                            struct HasPassword(bool);
                            let seen_forms = js_sys::Set::new(&Array::new());
                            let mut classified_forms = HashMap::< HasMark,
                            HashMap::< HasPassword,
                            Vec < FoundForm >>>:: new();
                            // Inspired by browserpass
                            #[derive(PartialEq, Eq, Clone, Copy)]
                            enum SelType {
                                User,
                                Password,
                            }
                            for (
                                sel_type,
                                any_input_sel,
                            ) in Iterator::chain(
                                USER_SELS.iter().map(|x| (SelType::User, x)),
                                PASSWORD_SELS.iter().map(|x| (SelType::Password, x)),
                            ) {
                                let any_input_res = doc.evaluate(any_input_sel, &doc).unwrap();
                                while let Some(any_input_node) = any_input_res.iterate_next().unwrap() {
                                    let any_input = any_input_node.dyn_into::<HtmlInputElement>().unwrap();
                                    let Some(form) = any_input.form() else {
                                        continue;
                                    };
                                    if seen_forms.has(&form) {
                                        continue;
                                    }
                                    seen_forms.add(&form);
                                    let has_mark;
                                    shed!{
                                        'done _;
                                        for prop in ["id", "name", "class", "action"] {
                                            for marker in [
                                                "login",
                                                "log-in",
                                                "log_in",
                                                "signin",
                                                "sign-in",
                                                "sign_in",
                                            ] {
                                                if form
                                                    .get_attribute(prop)
                                                    .as_ref()
                                                    .map(|x| x.to_ascii_lowercase())
                                                    .as_ref()
                                                    .map(|x| x.as_str()) ==
                                                    Some(marker) {
                                                    has_mark = HasMark(true);
                                                    break 'done;
                                                }
                                            }
                                        }
                                        has_mark = HasMark(false);
                                    }
                                    let password;
                                    shed!{
                                        'done _;
                                        if sel_type == SelType::Password {
                                            password = Some(any_input.clone());
                                            break 'done;
                                        }
                                        for sel in PASSWORD_SELS {
                                            let res = doc.evaluate(&sel, &form).unwrap();
                                            while let Some(node) = res.iterate_next().unwrap() {
                                                password = Some(node.dyn_into::<HtmlInputElement>().unwrap());
                                                break 'done;
                                            }
                                        }
                                        password = None;
                                    }
                                    let has_password = HasPassword(password.is_some());
                                    let out = FoundForm {
                                        form: form,
                                        searched_for_user: sel_type == SelType::User,
                                        user: if sel_type == SelType::User {
                                            Some(any_input)
                                        } else {
                                            None
                                        },
                                        password: password,
                                    };
                                    if has_mark.0 {
                                        match (sel_type, out.password.is_some()) {
                                            (SelType::User, true) => {
                                                user_input = out.user;
                                                password_input = out.password;
                                                break 'found_inputs;
                                            },
                                            (_, true) => {
                                                selected_form = out;
                                                break 'selected_form;
                                            },
                                            _ => { },
                                        }
                                    }
                                    classified_forms
                                        .entry(has_mark)
                                        .or_default()
                                        .entry(has_password)
                                        .or_default()
                                        .push(out);
                                }
                            }
                            for want_mark in [true, false] {
                                for want_password in [true, false] {
                                    for candidate in classified_forms
                                        .entry(HasMark(want_mark))
                                        .or_default()
                                        .remove(&HasPassword(want_password))
                                        .unwrap_or_default() {
                                        selected_form = candidate;
                                        break 'selected_form;
                                    }
                                }
                            }
                            // No result
                            return;
                        }
                        if selected_form.searched_for_user {
                            user_input = selected_form.user;
                        }
                        else {
                            shed!{
                                'found_user _;
                                for user_sel in USER_SELS {
                                    let user_res = doc.evaluate(user_sel, &selected_form.form).unwrap();
                                    while let Some(node) = user_res.iterate_next().unwrap() {
                                        user_input = Some(node.dyn_into::<HtmlInputElement>().unwrap());
                                        break 'found_user;
                                    }
                                }
                                user_input = None;
                            }
                        }
                        password_input = selected_form.password;
                    }
                    if let Some(i) = user_input {
                        i.set_value(&req_user);
                    }
                    if let Some(i) = password_input {
                        i.set_value(&req_password);
                    }
                },
                ToContent::FillField(text) => {
                    if let Some(last_focus) = last_focus.borrow().as_ref() {
                        last_focus.set_value(&text);
                    }
                },
            }
        }
    }) as Box<dyn Fn(JsValue, JsValue, Function)>);
    browser().runtime().on_message().add_listener(message_listener.as_ref().unchecked_ref());
    set_root_non_dom((focus_listener, message_listener));
}
