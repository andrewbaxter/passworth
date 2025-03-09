use {
    super::{
        dbutil::open_privdb,
        privdb,
    },
    crate::{
        FactorTree,
        FactorTreeVariant,
    },
    flowcontrol::shed,
    gtk4::{
        gdk::{
            prelude::DisplayExt,
            Key,
            ModifierType,
            Monitor,
        },
        gio::prelude::ListModelExt,
        glib::{
            object::{
                Cast,
                ObjectExt,
            },
        },
        prelude::{
            BoxExt,
            ButtonExt,
            EditableExt,
            EntryExt,
            GridExt,
            GtkWindowExt,
            RangeExt,
            RootExt,
            WidgetExt,
        },
        Align,
        Application,
        Label,
    },
    gtk4_layer_shell::LayerShell,
    loga::{
        conversion::ResultIgnore,
        ea,
        Log,
        ResultContext,
    },
    openpgp_card_sequoia::state::Open,
    passworth_native::{
        config::latest::ConfigCredSmartcards,
        crypto::{
            self,
            get_card_pubkey,
            local_decrypt,
            local_encrypt,
            CardStream,
        },
        error::{
            FromAnyErr,
            ToUiErr,
            UiErr,
        },
        generate::{
            self,
            bip39,
            BIP39_PHRASELEN,
        },
    },
    rand::{
        rng,
        RngCore,
    },
    rusqlite::Connection,
    sequoia_openpgp::serialize::stream::{
        Encryptor2,
        LiteralWriter,
        Message,
        Recipient,
    },
    std::{
        cell::RefCell,
        collections::{
            hash_map::Entry,
            HashMap,
            HashSet,
        },
        future::Future,
        io::Write,
        path::PathBuf,
        rc::Rc,
        sync::{
            Arc,
            Mutex,
        },
        time::{
            Duration,
            Instant,
        },
    },
    tokio::{
        select,
        sync::{
            mpsc,
            oneshot,
        },
    },
};

fn add_shortcut(w: &impl gtk4::glib::object::IsA<gtk4::Widget>, keys: &[Key], f: impl 'static + Clone + Fn()) {
    let shortcut = gtk4::ShortcutController::new();
    shortcut.set_scope(gtk4::ShortcutScope::Global);
    for key in keys {
        shortcut.add_shortcut(
            gtk4::Shortcut::builder()
                .trigger(&gtk4::KeyvalTrigger::new(*key, ModifierType::empty()))
                .action(&gtk4::CallbackAction::new({
                    let f = f.clone();
                    move |_, _| {
                        f();
                        return gtk4::glib::Propagation::Stop;
                    }
                }))
                .build(),
        );
    }
    w.add_controller(shortcut);
}

pub struct FgState {
    pub log: Log,
    pub last_prompts: Mutex<HashMap<usize, Instant>>,
}

async fn do_form_dialog<
    T: 'static,
>(
    app: &Application,
    mut initial_warning: Option<String>,
    title: Title,
    body: &impl gtk4::glib::object::IsA<gtk4::Widget>,
    tab_order: Option<Vec<gtk4::Widget>>,
    f: impl Fn() -> Result<T, String> + 'static,
) -> Option<T> {
    let (res_tx, res_rx) = oneshot::channel();
    let layout = vbox();
    let warning = {
        let w = label(&initial_warning.take().unwrap_or_default());
        w.add_css_class("error");
        if w.label().as_str().is_empty() {
            w.set_visible(false);
        }
        layout.append(&w);
        w
    };
    layout.append(body);
    let submit =
        gtk4::Button::builder().label("Ok").halign(gtk4::Align::End).css_classes(["suggested-action"]).build();
    layout.append(&submit);
    submit.set_receives_default(true);
    submit.connect_clicked({
        let res_tx = RefCell::new(Some(res_tx));
        move |_button| {
            match f() {
                Ok(r) => {
                    res_tx.borrow_mut().take().unwrap().send(r).ignore();
                },
                Err(e) => {
                    warning.set_label(&e);
                    warning.set_visible(true);
                },
            }
        }
    });
    if let Some(mut order) = tab_order {
        // No sane way to set tab order...
        order.push(submit.clone().into());
        layout.connect_realize(move |w| {
            let order = order.clone();
            w.root().unwrap().connect_move_focus(move |root, direction| {
                let mut at = 0i32;
                if let Some(true_focus) = root.focus() {
                    for (i, w) in order.iter().enumerate() {
                        let i = i as i32;
                        if true_focus.is_ancestor(w) {
                            at = i;
                            break;
                        }
                    }
                }
                let mut next = at + match direction {
                    gtk4::DirectionType::TabForward => 1,
                    gtk4::DirectionType::TabBackward => -1,
                    gtk4::DirectionType::Up => -1,
                    gtk4::DirectionType::Down => 1,
                    gtk4::DirectionType::Left => -1,
                    gtk4::DirectionType::Right => 1,
                    _ => 1,
                };
                if next < 0 {
                    next = order.len() as i32 + next;
                }
                if next >= order.len() as i32 {
                    next -= order.len() as i32;
                }
                let next = &order[next as usize];
                next.parent().unwrap().set_focus_child(Some(next));
            });
        });
    }
    {
        // No sane way to set default actions...
        let mut stack = vec![gtk4::Widget::from(layout.clone())];
        while let Some(top) = stack.pop() {
            if let Some(top) = top.downcast_ref::<gtk4::Entry>() {
                top.connect_activate({
                    let submit = submit.clone();
                    move |_| {
                        submit.emit_clicked();
                    }
                });
            }
            if let Some(top) = top.downcast_ref::<gtk4::PasswordEntry>() {
                top.connect_activate({
                    let submit = submit.clone();
                    move |_| {
                        submit.emit_clicked();
                    }
                });
            }
            let mut next = top.first_child();
            while let Some(at) = next {
                stack.push(at.clone());
                next = at.next_sibling();
            }
        }
    }
    return select!{
        _ = ui_window(&app, title, &layout) => None,
        r = res_rx => r.ok(),
    };
}

fn gen_token() -> Vec<u8> {
    let mut out = Vec::new();
    out.resize(32, 0u8);
    rng().fill_bytes(&mut out);
    return out;
}

async fn ui_recovery_entry(
    app: &Application,
    initial_warning: Option<String>,
    title: Title,
    message: &str,
) -> Option<Vec<u8>> {
    let layout = vbox();
    layout.append(&label(message));
    let word_set = Rc::new(bip39().iter().map(|x| *x).collect::<HashSet<_>>());
    let form_layout = grid();
    let mut entries = vec![];
    let mut tab_order = vec![];
    for i in 0 .. BIP39_PHRASELEN {
        let base_col = 1 + (i as i32 / (BIP39_PHRASELEN / 2) as i32) * 2;
        let row = 1 + i as i32 % (BIP39_PHRASELEN / 2) as i32;
        form_layout.attach(&halign_end(label(&format!("{}.", i + 1))), base_col, row, 1, 1);
        let entry = gtk4::Entry::builder().hexpand(true).build();
        entry.connect_changed({
            let word_set = word_set.clone();
            move |entry| {
                if word_set.contains(entry.text().as_str()) {
                    entry.remove_css_class("error");
                } else {
                    entry.add_css_class("error");
                }
            }
        });
        form_layout.attach(&entry, base_col + 1, row, 1, 1);
        entries.push(entry.clone());
        tab_order.push(entry.into());
    }
    layout.append(&form_layout);
    let Some(phrase) = do_form_dialog(&app, initial_warning, title, &layout, Some(tab_order), move || {
        for entry in &entries {
            if !word_set.contains(entry.text().as_str()) {
                return Err("Some words are spelled incorrectly".to_string());
            }
        }
        return Ok(
            entries.iter().map(|x| x.text().to_string()).collect::<Vec<_>>().join(" ").as_bytes().to_vec(),
        );
    }).await else {
        return None;
    };
    return Some(phrase);
}

async fn ui_choose(
    app: &Application,
    initial_warning: Option<String>,
    title: Title,
    choices: &Vec<Arc<FactorTree>>,
) -> Option<Arc<FactorTree>> {
    let (res_tx, mut res_rx) = mpsc::channel(1);
    let layout = vbox();
    attach_error(&layout, initial_warning);
    layout.append(&label("Choose an unlock method."));
    for (i, method) in choices.iter().enumerate() {
        let button = gtk4::Button::builder().label(&method.desc).build();
        if i == 0 {
            button.add_css_class("suggested-action");
        }
        button.connect_clicked({
            let method = method.clone();
            let res_tx = res_tx.clone();
            move |_| {
                res_tx.try_send(method.clone()).unwrap();
            }
        });
        layout.append(&button);
    }
    return select!{
        _ = ui_window(&app, title, &layout) => None,
        r = res_rx.recv() => r,
    };
}

async fn ui_get_smartcard(
    app: &Application,
    card_stream: &mut CardStream,
    initial_warning: Option<String>,
    title: Title,
    fingerprints: &[&str],
) -> Option<openpgp_card_sequoia::Card<Open>> {
    let layout = vbox();
    attach_error(&layout, initial_warning);
    layout.append(&label("Insert or swipe smartcard with GPG fingerprint:"));
    for fingerprint in fingerprints {
        layout.append(&monospace(&format!(" • {}", fingerprint)));
    }
    return select!{
        _ = ui_window(&app, title, &layout) => None,
        r = card_stream.next() => r,
    };
}

async fn ui_unlock_smartcard(
    log: &Log,
    app: &Application,
    initial_warning: Option<String>,
    title: Title,
    config: &ConfigCredSmartcards,
    state: &HashMap<String, Vec<u8>>,
) -> Result<Option<Vec<u8>>, UiErr> {
    let mut card_stream = CardStream::new(&log);

    // Try various cards
    let mut warning = initial_warning;
    loop {
        match async {
            // Pin entry
            let pin = if !config.fixed_pin {
                const KEYS: &[&[Key]] =
                    &[
                        &[Key::Arabic_0, Key::KP_0, Key::N, Key::B],
                        &[Key::Arabic_1, Key::KP_1, Key::M, Key::X],
                        &[Key::Arabic_2, Key::KP_2, Key::comma, Key::C],
                        &[Key::Arabic_3, Key::KP_3, Key::period, Key::V],
                        &[Key::Arabic_4, Key::KP_4, Key::J, Key::S],
                        &[Key::Arabic_5, Key::KP_5, Key::K, Key::D],
                        &[Key::Arabic_6, Key::KP_6, Key::L, Key::F],
                        &[Key::Arabic_7, Key::KP_7, Key::U, Key::W],
                        &[Key::Arabic_8, Key::KP_8, Key::I, Key::E],
                        &[Key::Arabic_9, Key::KP_9, Key::O, Key::R],
                    ];
                let layout = vbox();
                attach_error(&layout, warning.take());
                layout.append(&label("Enter card PIN."));
                let digits =
                    gtk4::PasswordEntry::builder().hexpand(true).show_peek_icon(true).can_focus(false).build();
                let pin_layout = grid();
                for i in -1 .. 9 as i32 {
                    let column = if i == -1 {
                        0
                    } else {
                        i.rem_euclid(3)
                    };
                    let row = 3 - i.div_floor(3);
                    let value = (i + 1) as usize;
                    let button = gtk4::Button::builder().label(value.to_string()).can_focus(false).build();
                    button.connect_clicked({
                        let digits = digits.clone();
                        move |_button| {
                            digits.set_text(&format!("{}{}", digits.text().as_str(), value.to_string()));
                        }
                    });
                    add_shortcut(&button, KEYS[value], {
                        let button = button.clone();
                        move || button.emit_clicked()
                    });
                    pin_layout.attach(&button, column, row, 1, 1);
                }
                {
                    let button = gtk4::Button::builder().icon_name("edit-clear").can_focus(false).build();
                    button.connect_clicked({
                        let digits = digits.clone();
                        move |_button| {
                            digits.set_text("");
                        }
                    });
                    add_shortcut(&button, &[Key::BackSpace, Key::Delete], {
                        let button = button.clone();
                        move || button.emit_clicked()
                    });
                    pin_layout.attach(&button, 1, 4, 1, 1);
                }
                layout.append(&halign_center(pin_layout));
                layout.append(&digits);
                let pin = match do_form_dialog(&app, warning.take(), title.clone(), &layout, None, {
                    let digits = digits.clone();
                    move || {
                        return Ok(digits.text().to_string());
                    }
                }).await {
                    Some(x) => x,
                    None => {
                        return Ok(None);
                    },
                };
                Some(pin)
            } else {
                None
            };
            let card =
                match ui_get_smartcard(
                    app,
                    &mut card_stream,
                    warning.take(),
                    title.clone(),
                    &state.keys().map(|x: &String| x.as_str()).collect::<Vec<_>>(),
                ).await {
                    Some(c) => c,
                    None => {
                        return Ok(None);
                    },
                };
            let (card, pubkey) = get_card_pubkey(card).await?;
            let Some(card_config) =
                config.smartcards.iter().filter(|c| c.fingerprint == pubkey.fingerprint().to_string()).next() else {
                    return Ok(None);
                };
            let card = card.enter_pin(card_config.pin.clone().or(pin)).await?;
            match card
                .decrypt(
                    state
                        .get(&card_config.fingerprint)
                        .context_with(
                            "Missing stored state for smartcard with fingerprint",
                            ea!(fingerprint = card_config.fingerprint),
                        )?
                        .clone(),
                )
                .await? {
                crypto::MaybeNeedTouch::NeedTouch(card) => {
                    let layout = vbox();
                    if let Some(warning) = warning.take() {
                        layout.append(&label(&warning));
                    }
                    layout.append(
                        &label(&format!("Confirm the action on the smartcard {}", card_config.fingerprint)),
                    );
                    return select!{
                        _ = ui_window(&app, title.clone(), &layout) => Ok(None),
                        r = card.wait_for_touch() => {
                            let (_, decrypted) = r?;
                            Ok(Some(decrypted))
                        },
                    };
                },
                crypto::MaybeNeedTouch::Decryptor(_, decrypted) => {
                    return Ok(Some(decrypted));
                },
            }
        }.await {
            Ok(r) => return Ok(r),
            Err(e) => match e {
                UiErr::Internal(i) => {
                    log.log_err(loga::WARN, i);
                    warning = Some("Internal error, check logs for details.".to_string());
                    continue;
                },
                UiErr::External(e, i) => {
                    if let Some(i) = i {
                        log.log_err(loga::WARN, i);
                    }
                    warning = Some(e);
                    continue;
                },
                UiErr::InternalUnresolvable(e) => {
                    return Err(UiErr::InternalUnresolvable(e));
                },
            },
        }
    }
}

#[derive(Clone)]
enum Either {
    /// New, optionally old - old is only used for unlocking via old creds when
    /// replacing stateful factors (namely or and smartcard which use stored encrypted
    /// generated keys).
    New(Arc<FactorTree>, Option<Arc<FactorTree>>),
    Prev(Arc<FactorTree>),
}

const SPACING1: i32 = 8;
const SPACING2H: i32 = 16;
const SPACING2V: i32 = 8;

fn vbox() -> gtk4::Box {
    return gtk4::Box::builder().orientation(gtk4::Orientation::Vertical).spacing(SPACING1).build();
}

fn hbox() -> gtk4::Box {
    return gtk4::Box::builder().orientation(gtk4::Orientation::Horizontal).spacing(SPACING1).build();
}

fn grid() -> gtk4::Grid {
    return gtk4::Grid::builder()
        .row_spacing(SPACING1)
        .column_spacing(SPACING1)
        .row_homogeneous(true)
        .hexpand(true)
        .build();
}

struct DoCredsRes {
    prev_tokens: HashMap<String, Vec<u8>>,
    new_tokens: HashMap<String, Vec<u8>>,
    store_state: HashMap<String, Vec<u8>>,
}

fn label(text: &str) -> Label {
    return Label::builder()
        .label(text)
        .wrap(true)
        .wrap_mode(gtk4::pango::WrapMode::Word)
        .halign(Align::Start)
        .build();
}

fn monospace(text: &str) -> Label {
    let out = label(text);
    out.set_wrap(false);
    out.add_css_class("monospace");
    return out;
}

fn attach_error(layout: &gtk4::Box, error: Option<String>) {
    if let Some(t) = error {
        let l = label(&t);
        l.add_css_class("error");
        layout.append(&l);
    }
}

fn halign_start<T: gtk4::glib::object::IsA<gtk4::Widget>>(w: T) -> T {
    w.set_halign(Align::Start);
    return w;
}

fn halign_center<T: gtk4::glib::object::IsA<gtk4::Widget>>(w: T) -> T {
    w.set_halign(Align::Center);
    return w;
}

fn halign_end<T: gtk4::glib::object::IsA<gtk4::Widget>>(w: T) -> T {
    w.set_halign(Align::End);
    return w;
}

/// Exits when manually closed. Closes window when dropped.
async fn ui_window(app: &Application, title: Title, body: &impl gtk4::glib::object::IsA<gtk4::Widget>) {
    let (close_tx, close_rx) = oneshot::channel();
    let window = gtk4::ApplicationWindow::builder().application(app).title(&format!("Passworth - {}", match title {
        Title::Initialize(x) => format!("Initialize [{}]", x),
        Title::Unlock(x) => format!("Unlock [{}]", x),
        Title::Prompt(x) => format!("Prompt [{}]", x),
    })).resizable(false).build();
    window.init_layer_shell();
    window.set_layer(gtk4_layer_shell::Layer::Overlay);
    window.set_keyboard_mode(gtk4_layer_shell::KeyboardMode::Exclusive);
    window.connect_unrealize({
        let close_tx = RefCell::new(Some(close_tx));
        move |_| {
            close_tx.borrow_mut().take().unwrap().send(()).ignore();
        }
    });
    let display = RootExt::display(&window);
    let monitor_listener = display.monitors().connect_items_changed({
        let window = window.clone();
        move |list, position, removed_count, _added_count| {
            // Issues with layer-shell https://github.com/wmww/gtk-layer-shell/issues/135 -
            // just close the window for now
            for i in position .. position + removed_count {
                if window.monitor() == list.item(i).map(|x| x.dynamic_cast::<Monitor>().unwrap()) {
                    window.close();
                }
            }
        }
    });
    defer::defer(move || {
        display.monitors().disconnect(monitor_listener);
    });
    let wrap = vbox();
    wrap.set_margin_bottom(SPACING2V);
    wrap.set_margin_top(SPACING2V);
    wrap.set_margin_start(SPACING2H);
    wrap.set_margin_end(SPACING2H);
    wrap.set_halign(Align::Center);
    wrap.set_valign(Align::Center);
    wrap.append(body);
    window.set_child(Some(&wrap));
    add_shortcut(&window, &[Key::Escape], {
        let window = window.clone();
        move || window.close()
    });
    window.present();
    let _defer = defer::defer(move || {
        window.close();
    });
    close_rx.await.ignore();
}

#[derive(Clone)]
enum Title {
    Initialize(String),
    Unlock(String),
    Prompt(String),
}

/// Retry ui interaction as long as there are errors. `Ok(None)` aborts.
async fn ui_loop<
    T,
    F: Future<Output = Result<Option<T>, UiErr>>,
    N: FnMut(Application, Option<String>) -> F,
>(log: &loga::Log, app: &Application, mut f: N) -> Result<Option<T>, loga::Error> {
    let mut show_error = None;
    loop {
        match f(app.clone(), show_error.take()).await {
            Ok(r) => return Ok(r),
            Err(e) => match e {
                UiErr::External(e, e_internal) => {
                    if let Some(e_internal) = e_internal {
                        log.log_err(loga::WARN, e_internal);
                    };
                    show_error = Some(e);
                },
                UiErr::Internal(e) => {
                    log.log_err(
                        loga::WARN,
                        e.context("An unexpected issue occurred while unlocking/initializing unlock credentials."),
                    );
                    show_error = Some("An unexpected error occurred, see log for details.".to_string());
                },
                UiErr::InternalUnresolvable(e) => {
                    return Err(e);
                },
            },
        }
    };
}

async fn do_creds(
    app: Application,
    state: Arc<FgState>,
    token_changed: HashSet<String>,
    state_changed: HashSet<String>,
    mut prev_tokens: HashMap<String, Vec<u8>>,
    prev_state: HashMap<String, Vec<u8>>,
    mut show_error: Option<String>,
    start: Either,
) -> Result<Option<DoCredsRes>, UiErr> {
    let mut stack = vec![(start, true)];
    let mut new_tokens = HashMap::<String, Vec<u8>>::new();
    let mut store_state = HashMap::<String, Vec<u8>>::new();
    while let Some((at, descending)) = stack.pop() {
        match &at {
            Either::New(new, old) => {
                let log = state.log.fork(ea!(factor = new.id));
                let prev_variant = old.as_ref().map(|x| &x.variant);
                if new_tokens.contains_key(&new.id) {
                    // nop
                } else if Some(new) == old.as_ref() {
                    if let Some(token) = prev_tokens.get(&new.id) {
                        new_tokens.insert(new.id.clone(), token.clone());
                    } else {
                        stack.push((Either::New(new.clone(), old.clone()), true));
                        stack.push((Either::Prev(new.clone()), true));
                    }
                } else {
                    match &new.variant {
                        FactorTreeVariant::And(children) => {
                            if descending {
                                stack.push((at.clone(), false));
                                let mut match_old = HashMap::new();
                                if let Some(FactorTreeVariant::And(prev_children)) = prev_variant {
                                    for child in prev_children {
                                        match_old.insert(child.id.clone(), child.clone());
                                    }
                                }
                                for child in children.iter().rev() {
                                    if new_tokens.contains_key(&child.id) {
                                        continue;
                                    }
                                    stack.push((Either::New(child.clone(), match_old.remove(&child.id)), true));
                                }
                            } else {
                                let mut token = vec![];
                                for child in children {
                                    token.extend(new_tokens.get(&child.id).unwrap());
                                }
                                new_tokens.insert(new.id.clone(), token);
                            }
                        },
                        FactorTreeVariant::Or(children) => {
                            if descending {
                                stack.push((at.clone(), false));
                                let mut match_old = HashMap::new();
                                if let Some(FactorTreeVariant::Or(prev_children)) = prev_variant {
                                    for child in prev_children {
                                        match_old.insert(child.id.clone(), child.clone());
                                    }
                                }
                                for child in children.iter().rev() {
                                    if 
                                    // Need to generate sub-state for this child
                                    token_changed.contains(&child.id) || 
                                        // Need to descend so child can regen its own state
                                        state_changed.contains(&child.id) {
                                        stack.push(
                                            (Either::New(child.clone(), match_old.remove(&child.id)), true),
                                        );
                                    }
                                }
                                if let Some(FactorTreeVariant::Or(prev_children)) = prev_variant {
                                    let mut already_unlocked = false;
                                    for child in prev_children {
                                        if prev_tokens.contains_key(&child.id) {
                                            already_unlocked = true;
                                        }
                                    }
                                    if !already_unlocked {
                                        let Some(child) =
                                            ui_choose(
                                                &app,
                                                show_error.take(),
                                                Title::Unlock(new.desc.to_string()),
                                                &prev_children,
                                            ).await else {
                                                return Ok(None);
                                            };
                                        stack.push((Either::Prev(child), true));
                                    }
                                }
                            } else {
                                // Get or token
                                let token = shed!{
                                    'found _;
                                    if let Some(FactorTreeVariant::Or(prev_children)) = prev_variant {
                                        for child in prev_children {
                                            if let Some(key) = prev_tokens.get(&child.id) {
                                                break 'found local_decrypt(
                                                    &key,
                                                    prev_state
                                                        .get(&new.id)
                                                        .stack_context(&log, "Missing state for or")?,
                                                )
                                                    .stack_context(
                                                        &log,
                                                        "Error reading existing encrypted factor data",
                                                    )?
                                                    .stack_context(
                                                        &log,
                                                        "Unexpected error: token used for unlock failed during new-token generation",
                                                    )?;
                                            }
                                        }
                                    }
                                    break 'found gen_token();
                                };
                                let mut state = match prev_state.get(&new.id) {
                                    Some(states) => serde_json::from_slice::<HashMap<String, Vec<u8>>>(
                                        &states,
                                    ).stack_context(&log, "Error reading existing encrypted factor data")?,
                                    None => HashMap::new(),
                                };
                                for child in children {
                                    let Entry::Vacant(v) = state.entry(child.id.clone()) else {
                                        continue;
                                    };
                                    v.insert(local_encrypt(new_tokens.get(&child.id).unwrap(), &token));
                                }
                                store_state.insert(new.id.clone(), serde_json::to_vec(&state).unwrap());
                                new_tokens.insert(new.id.clone(), token);
                            }
                        },
                        FactorTreeVariant::Password => {
                            let layout = vbox();
                            attach_error(&layout, show_error.take());
                            layout.append(&label(&format!("Enter new password for [{}].", new.desc)));
                            let generators =
                                [
                                    ("Alphanumeric", generate::gen_alphanum as fn(usize) -> String),
                                    ("Use anywhere", generate::gen_safe_alphanum),
                                    ("Alphanumeric and symbols", generate::gen_alphanum_symbols),
                                ];
                            let password = gtk4::PasswordEntry::builder().hexpand(true).build();
                            password.set_show_peek_icon(true);
                            let confirm_password = gtk4::PasswordEntry::builder().hexpand(true).build();
                            let generate_dropdown = gtk4::DropDown::builder().build();
                            let generate_len = gtk4::Scale::builder().draw_value(true).hexpand(true).build();
                            let generate_button = gtk4::Button::builder().label("Generate").build();
                            {
                                let form_layout = grid();
                                form_layout.attach(&halign_end(label("Password")), 1, 1, 1, 1);
                                form_layout.attach(&password, 2, 1, 1, 1);
                                form_layout.attach(&halign_end(label("Confirm")), 1, 2, 1, 1);
                                form_layout.attach(&confirm_password, 2, 2, 1, 1);
                                layout.append(&form_layout);
                            }
                            {
                                let generate_layout = vbox();
                                generate_layout.set_margin_bottom(SPACING1);
                                generate_layout.set_margin_top(SPACING1);
                                generate_layout.set_margin_start(SPACING1);
                                generate_layout.set_margin_end(SPACING1);
                                let line1 = hbox();
                                let dropdown_strings = gtk4::StringList::new(&[]);
                                for (title, _) in generators {
                                    dropdown_strings.append(&title);
                                }
                                generate_dropdown.set_model(Some(&dropdown_strings));
                                line1.append(&generate_dropdown);
                                line1.append(&generate_button);
                                generate_layout.append(&line1);
                                let line2 = hbox();
                                line2.append(&label("Length"));
                                generate_len.set_round_digits(0);
                                generate_len.set_range(5., 50.);
                                generate_len.set_value(16.);
                                line2.append(&generate_len);
                                generate_layout.append(&line2);
                                layout.append(
                                    &gtk4::Expander::builder()
                                        .label("Generate")
                                        .child(&gtk4::Frame::builder().child(&generate_layout).build())
                                        .build(),
                                );
                            }
                            generate_button.connect_clicked({
                                let dropdown = generate_dropdown.clone();
                                let password = password.clone();
                                let confirm_password = confirm_password.clone();
                                move |_button| {
                                    confirm_password.set_text("");
                                    password.set_text(
                                        &(generators[dropdown.selected() as usize].1)(generate_len.value() as usize),
                                    );
                                }
                            });
                            let Some(password) =
                                do_form_dialog(
                                    &app,
                                    show_error.take(),
                                    Title::Initialize(new.desc.clone()),
                                    &layout,
                                    None,
                                    {
                                        move || {
                                            if password.text() == confirm_password.text() {
                                                return Ok(password.text().as_bytes().to_vec());
                                            } else {
                                                return Err("Password mismatch".to_string());
                                            }
                                        }
                                    },
                                ).await else {
                                    return Ok(None);
                                };
                            new_tokens.insert(new.id.clone(), password);
                        },
                        FactorTreeVariant::Smartcards(c) => {
                            // Retrieve existing state data, or empty
                            let mut state = match prev_state.get(&new.id) {
                                Some(state) => serde_json::from_slice::<HashMap<String, Vec<u8>>>(
                                    &state,
                                ).stack_context(&log, "Error reading existing encrypted factor data")?,
                                None => HashMap::new(),
                            };

                            // Get token from old smartcards or generate a new one if there were none
                            let token = shed!{
                                'found _;
                                if let Some(key) = prev_tokens.get(&new.id) {
                                    break 'found key.clone();
                                }
                                if let Some(FactorTreeVariant::Smartcards(prev_children)) = prev_variant {
                                    let Some(token) =
                                        ui_unlock_smartcard(
                                            &log,
                                            &app,
                                            show_error.take(),
                                            Title::Initialize(new.desc.to_string()),
                                            prev_children,
                                            &state,
                                        ).await? else {
                                            return Ok(None);
                                        };
                                    break 'found token;
                                }
                                break 'found gen_token();
                            };

                            // Scan all new smartcards and generate new state data for them
                            let mut remaining_new_fingerprints = HashSet::new();
                            for child in &c.smartcards {
                                if state.contains_key(&child.fingerprint) {
                                    continue;
                                }
                                remaining_new_fingerprints.insert(child.fingerprint.clone());
                            }
                            let mut card_stream = CardStream::new(&log);
                            while !remaining_new_fingerprints.is_empty() {
                                let Some(mut card) =
                                    ui_get_smartcard(
                                        &app,
                                        &mut card_stream,
                                        show_error.take(),
                                        Title::Initialize(new.desc.to_string()),
                                        &remaining_new_fingerprints.iter().map(|x| x.as_str()).collect::<Vec<_>>(),
                                    ).await else {
                                        return Ok(None);
                                    };
                                let mut card_tx = card.transaction().context("Error starting smartcard transaction")?;
                                let Some(pubkey) =
                                    card_tx
                                        .public_key(openpgp_card_sequoia::types::KeyType::Decryption)
                                        .map_err(|e| loga::err(e.to_string()))? else {
                                        show_error = Some("Couldn't determine public key for card.".to_string());
                                        continue;
                                    };
                                let fingerprint = pubkey.fingerprint().to_string();
                                if !remaining_new_fingerprints.remove(&fingerprint) {
                                    show_error =
                                        Some(format!("Smartcard had the wrong fingerprint: {}", fingerprint));
                                    continue;
                                };
                                let mut sink = vec![];
                                let message = Message::new(&mut sink);
                                let message =
                                    Encryptor2::for_recipients(message, vec![Recipient::from(&pubkey)])
                                        .build()
                                        .map_err(|e| loga::err(e.to_string()))
                                        .context("Error building encryptor")?;
                                let mut w =
                                    LiteralWriter::new(message)
                                        .build()
                                        .map_err(|e| loga::err(e.to_string()))
                                        .context("Error forming encryption writer")?;
                                w.write_all(&token).context("Error streaming data to encrypt")?;
                                w
                                    .finalize()
                                    .map_err(|e| loga::err(e.to_string()))
                                    .context("Error finalizing encryption")?;
                                state.insert(fingerprint.clone(), sink);
                            }

                            // Bundle + store everything
                            store_state.insert(new.id.clone(), serde_json::to_vec(&state).unwrap());
                            new_tokens.insert(new.id.clone(), token);
                        },
                        FactorTreeVariant::RecoveryPhrase => {
                            // Show
                            let layout = vbox();
                            attach_error(&layout, show_error.take());
                            layout.append(
                                &label("Write down this phrase list, with numbers, and store it somewhere secure."),
                            );
                            let form_layout = grid();
                            let phrase = generate::gen_bip39();
                            for (i, word) in phrase.iter().enumerate() {
                                let base_col = (i as i32 / (BIP39_PHRASELEN / 2) as i32) * 2;
                                let row = i as i32 % (BIP39_PHRASELEN / 2) as i32;
                                form_layout.attach(&halign_end(label(&format!("{}.", i + 1))), base_col, row, 1, 1);
                                let word_label = monospace(word);
                                word_label.set_hexpand(true);
                                form_layout.attach(&halign_start(word_label), base_col + 1, row, 1, 1);
                            }
                            layout.append(&form_layout);
                            let Some(_) =
                                do_form_dialog(
                                    &app,
                                    show_error.take(),
                                    Title::Initialize(new.desc.to_string()),
                                    &layout,
                                    None,
                                    || {
                                        return Ok(());
                                    },
                                ).await else {
                                    return Ok(None);
                                };
                            let phrase = phrase.join(" ").as_bytes().to_vec();

                            // Confirm
                            let Some(confirm_passphrase) =
                                ui_recovery_entry(
                                    &app,
                                    show_error.take(),
                                    Title::Initialize(new.desc.to_string()),
                                    "Confirm the phrase.",
                                ).await else {
                                    return Ok(None);
                                };
                            if confirm_passphrase != phrase {
                                return Err(
                                    UiErr::external(
                                        "Recovery phrases didn't match; make sure you wrote down the correct order as well.",
                                    ),
                                );
                            }

                            // Save
                            new_tokens.insert(new.id.clone(), phrase);
                        },
                    }
                }
            },
            Either::Prev(prev) => {
                let log = state.log.fork(ea!(factor = prev.id));
                if prev_tokens.contains_key(&prev.id) {
                    // nop
                } else {
                    match &prev.variant {
                        FactorTreeVariant::And(children) => {
                            if descending {
                                stack.push((at.clone(), false));
                                for child in children.iter().rev() {
                                    if prev_tokens.contains_key(&child.id) {
                                        continue;
                                    }
                                    stack.push((Either::Prev(child.clone()), true));
                                }
                            } else {
                                let mut token = vec![];
                                for child in children {
                                    token.extend(prev_tokens.get(&child.id).unwrap());
                                }
                                prev_tokens.insert(prev.id.clone(), token);
                            }
                        },
                        FactorTreeVariant::Or(children) => {
                            let state =
                                serde_json::from_slice::<HashMap<String, Vec<u8>>>(
                                    &prev_state
                                        .get(&prev.id)
                                        .context_with("State for factor missing in database", ea!(factor = prev.id))?,
                                ).context_with("Error parsing stored factor state", ea!(factor = prev.id))?;
                            let mut done = false;
                            for child in children {
                                if let Some(key) = prev_tokens.get(&child.id) {
                                    let token =
                                        match local_decrypt(
                                            &key,
                                            &state
                                                .get(&child.id)
                                                .context(&format!("Missing child state for [{}] in or", child.id))?,
                                        ).context("Error parsing stored state for factor")? {
                                            Some(t) => t,
                                            None => return Err(
                                                UiErr::External(
                                                    format!("Incorrect factor [{}], decryption failed", child.id),
                                                    None,
                                                ),
                                            ),
                                        };
                                    prev_tokens.insert(prev.id.clone(), token);
                                    done = true;
                                }
                            }
                            if !done {
                                stack.push((at.clone(), false));
                                let Some(child) =
                                    ui_choose(
                                        &app,
                                        show_error.take(),
                                        Title::Unlock(prev.desc.to_string()),
                                        children,
                                    ).await else {
                                        return Ok(None);
                                    };
                                stack.push((Either::Prev(child), true));
                            }
                        },
                        FactorTreeVariant::Password => {
                            let layout = vbox();
                            attach_error(&layout, show_error.take());
                            layout.append(&label(&format!("Enter password for {}.", prev.desc)));
                            let form_layout = grid();
                            form_layout.attach(&halign_end(label("Password")), 1, 1, 1, 1);
                            let password = {
                                let password = gtk4::PasswordEntry::builder().hexpand(true).build();
                                form_layout.attach(&password, 2, 1, 1, 1);
                                password
                            };
                            layout.append(&form_layout);
                            let Some(password) =
                                do_form_dialog(
                                    &app,
                                    show_error.take(),
                                    Title::Unlock(prev.desc.to_string()),
                                    &layout,
                                    None,
                                    {
                                        move || {
                                            return Ok(password.text().as_bytes().to_vec());
                                        }
                                    },
                                ).await else {
                                    return Ok(None);
                                };
                            prev_tokens.insert(prev.id.clone(), password);
                        },
                        FactorTreeVariant::Smartcards(c) => {
                            let state =
                                serde_json::from_slice::<HashMap<String, Vec<u8>>>(
                                    &prev_state
                                        .get(&prev.id)
                                        .stack_context(&log, "Pretoken for factor missing in database")?,
                                ).stack_context(&log, "Unable to deserialize smartcards state")?;
                            let Some(token) =
                                ui_unlock_smartcard(
                                    &log,
                                    &app,
                                    show_error.take(),
                                    Title::Unlock(prev.desc.to_string()),
                                    c,
                                    &state,
                                ).await? else {
                                    return Ok(None);
                                };
                            prev_tokens.insert(prev.id.clone(), token);
                        },
                        FactorTreeVariant::RecoveryPhrase => {
                            let Some(phrase) =
                                ui_recovery_entry(
                                    &app,
                                    show_error.take(),
                                    Title::Unlock(prev.desc.to_string()),
                                    "Enter the recovery phrase words in the correct order.",
                                ).await else {
                                    return Ok(None);
                                };
                            prev_tokens.insert(prev.id.clone(), phrase);
                        },
                    }
                }
            },
        }
    }
    return Ok(Some(DoCredsRes {
        prev_tokens: prev_tokens,
        new_tokens: new_tokens,
        store_state: store_state,
    }));
}

pub struct B2FUnlock {
    pub privdb_path: PathBuf,
    pub root_factor: Arc<FactorTree>,
    pub state: HashMap<String, Vec<u8>>,
}

pub struct B2FUnlockResult {
    pub privdbc: Connection,
    pub root_token: String,
    pub tokens: HashMap<String, Vec<u8>>,
}

pub async fn do_unlock(
    state: Arc<FgState>,
    app: &Application,
    args: Arc<B2FUnlock>,
) -> Result<Option<B2FUnlockResult>, loga::Error> {
    return ui_loop(&state.log.clone(), app, move |app, show_err| {
        let args = args.clone();
        let state = state.clone();
        async move {
            let res =
                match do_creds(
                    app,
                    state,
                    HashSet::new(),
                    HashSet::new(),
                    HashMap::new(),
                    args.state.clone(),
                    show_err,
                    Either::Prev(args.root_factor.clone()),
                ).await? {
                    Some(x) => Arc::new(x),
                    None => return Ok(None),
                };
            let privdbc = gtk4::gio::spawn_blocking({
                let args = args.clone();
                let res = res.clone();
                move || {
                    // Confirm token
                    let mut privdbc =
                        open_privdb(
                            &args.privdb_path,
                            &zbase32::encode_full_bytes(&res.prev_tokens.get(&args.root_factor.id).unwrap()),
                        )?;
                    privdb::migrate(
                        &mut privdbc,
                    ).context_with("Error setting up priv database", ea!(path = args.privdb_path.to_string_lossy()))?;
                    return Ok(privdbc) as Result<_, loga::Error>;
                }
            }).await.any_context()?.to_ui_err_external("Failed to unlock database")?;
            return Ok(Some(B2FUnlockResult {
                privdbc: privdbc,
                root_token: zbase32::encode_full_bytes(&res.prev_tokens.get(&args.root_factor.id).unwrap().clone()),
                tokens: res.prev_tokens.clone(),
            }));
        }
    }).await;
}

pub struct B2FInitialize {
    pub privdbc: Option<Connection>,
    pub root_factor: Arc<FactorTree>,
    pub tokens_changed: HashSet<String>,
    pub state_changed: HashSet<String>,
    pub prev_tokens: HashMap<String, Vec<u8>>,
    pub prev_root_factor: Option<Arc<FactorTree>>,
    pub prev_state: HashMap<String, Vec<u8>>,
}

pub struct B2FInitializeResult {
    pub root_token: Option<String>,
    pub store_state: HashMap<String, Vec<u8>>,
}

pub async fn do_initialize(
    state: Arc<FgState>,
    app: &Application,
    args: Arc<B2FInitialize>,
) -> Result<Option<B2FInitializeResult>, loga::Error> {
    let Some(r) = ui_loop(&state.log.clone(), app, {
        let args = args.clone();
        move |app, show_err| do_creds(
            app,
            state.clone(),
            args.tokens_changed.clone(),
            args.state_changed.clone(),
            args.prev_tokens.clone(),
            args.prev_state.clone(),
            show_err,
            Either::New(args.root_factor.clone(), args.prev_root_factor.clone()),
        )
    }).await? else {
        return Ok(None);
    };
    return Ok(Some(B2FInitializeResult {
        root_token: r.new_tokens.get(&args.root_factor.id).map(|x| zbase32::encode_full_bytes(&x)),
        store_state: r.store_state,
    }));
}

pub struct B2FPrompt {
    pub prompt_rules: HashMap<usize, (String, u64)>,
}

pub async fn do_prompt(
    state: Arc<FgState>,
    app: &Application,
    args: Arc<B2FPrompt>,
) -> Result<Option<bool>, loga::Error> {
    let now = Instant::now();
    let mut elapsed_rule_desc = None;
    for (rule_id, (rule_desc, rule_remember)) in &args.prompt_rules {
        if let Some(last) = state.last_prompts.lock().unwrap().get(&rule_id) {
            if last.checked_add(Duration::from_secs(*rule_remember)).map(|x| x > now).unwrap_or(true) {
                continue;
            }
        }
        elapsed_rule_desc = Some(rule_desc.clone());
        break;
    }
    let Some(elapsed_rule_desc) = elapsed_rule_desc else {
        return Ok(Some(true));
    };
    let out = ui_loop(&state.log, app, move |app, _| {
        let elapsed_rule_desc = elapsed_rule_desc.clone();
        async move {
            let (res_tx, res_rx) = oneshot::channel();
            let res_tx = Rc::new(RefCell::new(Some(res_tx)));
            let layout = vbox();
            layout.append(&label("Confirm request by application matching rule?"));
            layout.append(&halign_center(monospace(&elapsed_rule_desc)));
            let button_layout = hbox();
            button_layout.append(&{
                let button = gtk4::Button::builder().label("Cancel").halign(gtk4::Align::End).build();
                button.connect_clicked({
                    let res_tx = res_tx.clone();
                    move |_button| {
                        res_tx.borrow_mut().take().unwrap().send(false).ignore();
                    }
                });
                button
            });
            button_layout.append(&{
                let button =
                    gtk4::Button::builder()
                        .label("Ok")
                        .halign(gtk4::Align::End)
                        .css_classes(["suggested-action"])
                        .build();
                button.set_receives_default(true);
                button.connect_clicked({
                    let res_tx = res_tx.clone();
                    move |_button| {
                        res_tx.borrow_mut().take().unwrap().send(true).ignore();
                    }
                });
                add_shortcut(&button, &[Key::KP_Enter, Key::Return], {
                    let button = button.clone();
                    move || button.emit_clicked()
                });
                button
            });
            return select!{
                _ = ui_window(&app, Title::Prompt(elapsed_rule_desc.clone()), &layout) => Ok(None),
                r = res_rx => Ok(r.ok())
            };
        }
    }).await?;
    if out == Some(true) {
        for rule_id in args.prompt_rules.keys() {
            state.last_prompts.lock().unwrap().insert(*rule_id, now);
        }
    }
    return Ok(out);
}

pub enum B2F {
    Initialize(B2FInitialize, oneshot::Sender<Result<Option<B2FInitializeResult>, loga::Error>>),
    Unlock(B2FUnlock, oneshot::Sender<Result<Option<B2FUnlockResult>, loga::Error>>),
    Prompt(B2FPrompt, oneshot::Sender<Result<Option<bool>, loga::Error>>),
}
