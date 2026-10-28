//! GTK helper for passworth-server. Reads `ToUi` messages from stdin (one JSON object
//! per line), shows windows, and writes `FromUi` messages to stdout. It holds no
//! secrets beyond what the user is currently typing, and exits when stdin closes.
use {
    flowcontrol::superif,
    gtk4::{
        Align,
        Application,
        Label,
        gdk::{
            Key,
            ModifierType,
            Monitor,
            prelude::DisplayExt,
        },
        gio::prelude::{
            ApplicationExt,
            ListModelExt,
        },
        glib::object::Cast,
        prelude::{
            ApplicationExtManual,
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
    },
    gtk4_layer_shell::LayerShell,
    passworth_native::{
        generate::{
            BIP39_PHRASELEN,
            bip39,
            self,
        },
        uiproto::{
            Body,
            FromUi,
            Title,
            ToUi,
            UiValue,
        },
    },
    std::{
        cell::{
            Cell,
            RefCell,
        },
        collections::{
            HashMap,
            HashSet,
        },
        io::{
            BufRead,
            Write,
        },
        rc::Rc,
        time::Duration,
    },
};

const SPACING1: i32 = 8;
const SPACING2H: i32 = 16;
const SPACING2V: i32 = 8;
const PROMPT_ARM_DELAY: Duration = Duration::from_millis(750);

struct OpenWindow {
    window: gtk4::Window,
    /// Set once a result/cancel has been sent (or the server closed it) so the close
    /// handler doesn't also send `Cancelled`.
    finished: Rc<Cell<bool>>,
}

struct State {
    app: Application,
    windows: RefCell<HashMap<u64, OpenWindow>>,
}

impl State {
    fn send(&self, msg: FromUi) {
        let mut line = serde_json::to_vec(&msg).unwrap();
        line.push(b'\n');
        let stdout = std::io::stdout();
        let mut stdout = stdout.lock();
        if stdout.write_all(&line).and_then(|_| stdout.flush()).is_err() {
            // Server went away
            self.app.quit();
        }
    }

    /// Answer a window and close it.
    fn finish(&self, id: u64, value: UiValue) {
        let Some(w) = self.windows.borrow_mut().remove(&id) else {
            return;
        };
        w.finished.set(true);
        self.send(FromUi::Result {
            id: id,
            value: value,
        });
        w.window.close();
    }

    /// Server asked to close a window; no response.
    fn close(&self, id: u64) {
        let Some(w) = self.windows.borrow_mut().remove(&id) else {
            return;
        };
        w.finished.set(true);
        w.window.close();
    }
}

fn main() {
    // This process sees what the user types; keep it out of core dumps.
    unsafe {
        libc::prctl(libc::PR_SET_DUMPABLE, 0);
    }
    let app =
        gtk4::Application::builder()
            .application_id("x.passworth.ui")
            .flags(gtk4::gio::ApplicationFlags::NON_UNIQUE)
            .build();
    app.connect_activate(move |app| {
        let hold = app.hold();
        let state = Rc::new(State {
            app: app.clone(),
            windows: RefCell::new(HashMap::new()),
        });

        // Stdin reader thread -> main loop
        let (tx, rx) = async_channel::unbounded::<Option<ToUi>>();
        std::thread::spawn(move || {
            let stdin = std::io::stdin();
            for line in stdin.lock().lines() {
                let Ok(line) = line else {
                    break;
                };
                if line.trim().is_empty() {
                    continue;
                }
                match serde_json::from_str::<ToUi>(&line) {
                    Ok(m) => {
                        if tx.send_blocking(Some(m)).is_err() {
                            break;
                        }
                    },
                    Err(e) => {
                        eprintln!("passworth-ui: invalid message from server: {}", e);
                    },
                }
            }
            _ = tx.send_blocking(None);
        });
        gtk4::glib::spawn_future_local({
            let state = state.clone();
            async move {
                let _hold = hold;
                while let Ok(msg) = rx.recv().await {
                    match msg {
                        Some(ToUi::Open { id, title, error, body }) => {
                            open_window(&state, id, title, error, body);
                        },
                        Some(ToUi::Close { id }) => {
                            state.close(id);
                        },
                        None => {
                            break;
                        },
                    }
                }
                state.app.quit();
            }
        });
    });
    app.run_with_args(&[] as &[String]);
}

fn open_window(state: &Rc<State>, id: u64, title: Title, error: Option<String>, body: Body) {
    let layout = vbox();
    attach_error(&layout, error);
    match body {
        Body::NewPassword { message } => {
            layout.append(&label(&message));
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
            let form = form_dialog(state, id, &layout, None, move || {
                if password.text() == confirm_password.text() {
                    return Ok(UiValue::Bytes(password.text().as_bytes().to_vec()));
                } else {
                    return Err("Password mismatch".to_string());
                }
            });
            show_window(state, id, title, &form);
        },
        Body::Password { message } => {
            layout.append(&label(&message));
            let form_layout = grid();
            form_layout.attach(&halign_end(label("Password")), 1, 1, 1, 1);
            let password = gtk4::PasswordEntry::builder().hexpand(true).build();
            form_layout.attach(&password, 2, 1, 1, 1);
            layout.append(&form_layout);
            let form = form_dialog(state, id, &layout, None, move || {
                return Ok(UiValue::Bytes(password.text().as_bytes().to_vec()));
            });
            show_window(state, id, title, &form);
        },
        Body::Choose { message, options } => {
            layout.append(&label(&message));
            for (i, option) in options.iter().enumerate() {
                let button = gtk4::Button::builder().label(option).build();
                if i == 0 {
                    button.add_css_class("suggested-action");
                }
                button.connect_clicked({
                    let state = state.clone();
                    move |_| {
                        state.finish(id, UiValue::Index(i));
                    }
                });
                layout.append(&button);
            }
            show_window(state, id, title, &layout);
        },
        Body::ShowPhrase { message, words } => {
            layout.append(&label(&message));
            let form_layout = grid();
            let per_col = (words.len() + 1) / 2;
            for (i, word) in words.iter().enumerate() {
                let base_col = (i / per_col) as i32 * 2;
                let row = (i % per_col) as i32;
                form_layout.attach(&halign_end(label(&format!("{}.", i + 1))), base_col, row, 1, 1);
                let word_label = monospace(word);
                word_label.set_hexpand(true);
                form_layout.attach(&halign_start(word_label), base_col + 1, row, 1, 1);
            }
            layout.append(&form_layout);
            let form = form_dialog(state, id, &layout, None, || Ok(UiValue::Ok));
            show_window(state, id, title, &form);
        },
        Body::EnterPhrase { message } => {
            layout.append(&label(&message));
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
            let form = form_dialog(state, id, &layout, Some(tab_order), move || {
                for entry in &entries {
                    if !word_set.contains(entry.text().as_str()) {
                        return Err("Some words are spelled incorrectly".to_string());
                    }
                }
                return Ok(
                    UiValue::Bytes(
                        entries
                            .iter()
                            .map(|x| x.text().to_string())
                            .collect::<Vec<_>>()
                            .join(" ")
                            .as_bytes()
                            .to_vec(),
                    ),
                );
            });
            show_window(state, id, title, &form);
        },
        Body::Pin { message } => {
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
            layout.append(&label(&message));
            let digits = gtk4::PasswordEntry::builder().hexpand(true).show_peek_icon(true).can_focus(false).build();
            let pin_layout = grid();
            for i in -1 .. 9 as i32 {
                let column = if i == -1 {
                    0
                } else {
                    i.rem_euclid(3)
                };
                let row = 3 - i.div_euclid(3);
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
            let form = form_dialog(state, id, &layout, None, move || {
                return Ok(UiValue::Text(digits.text().to_string()));
            });
            show_window(state, id, title, &form);
        },
        Body::Message { message } => {
            for (i, line) in message.lines().enumerate() {
                if i == 0 {
                    layout.append(&label(line));
                } else {
                    layout.append(&monospace(line));
                }
            }
            show_window(state, id, title, &layout);
        },
        Body::Prompt { rule, principal, paths } => {
            layout.append(&label("Confirm request by application matching rule?"));
            layout.append(&halign_center(monospace(&rule)));
            layout.append(&label(&format!("Requester: {}", principal)));
            layout.append(&label("Paths:"));
            const MAX_SHOWN_PATHS: usize = 8;
            for p in paths.iter().take(MAX_SHOWN_PATHS) {
                layout.append(&monospace(&format!(" • {}", p)));
            }
            if paths.len() > MAX_SHOWN_PATHS {
                layout.append(&label(&format!(" … and {} more", paths.len() - MAX_SHOWN_PATHS)));
            }
            let button_layout = hbox();
            button_layout.append(&{
                let button = gtk4::Button::builder().label("Cancel").halign(gtk4::Align::End).build();
                button.connect_clicked({
                    let state = state.clone();
                    move |_button| {
                        state.finish(id, UiValue::Bool(false));
                    }
                });
                button
            });
            button_layout.append(&{
                let button =
                    gtk4::Button::builder()
                        .label("Ok")
                        .hexpand(true)
                        .halign(gtk4::Align::End)
                        .css_classes(["suggested-action"])
                        .build();
                button.set_receives_default(true);
                button.connect_clicked({
                    let state = state.clone();
                    move |_button| {
                        state.finish(id, UiValue::Bool(true));
                    }
                });

                // Arm the approve button only after a short delay so a prompt appearing while
                // the user is typing can't be approved by an in-flight Enter keypress.
                button.set_sensitive(false);
                gtk4::glib::timeout_add_local_once(PROMPT_ARM_DELAY, {
                    let button = button.clone();
                    move || button.set_sensitive(true)
                });
                add_shortcut(&button, &[Key::KP_Enter, Key::Return], {
                    let button = button.clone();
                    move || if button.is_sensitive() {
                        button.emit_clicked()
                    }
                });
                button
            });
            layout.append(&button_layout);
            show_window(state, id, title, &layout);
        },
    }
}

/// Wrap a body in a dialog with Cancel/Ok buttons. `f` produces the result when Ok
/// is pressed, or a validation error to display.
fn form_dialog(
    state: &Rc<State>,
    id: u64,
    body: &impl gtk4::glib::object::IsA<gtk4::Widget>,
    tab_order: Option<Vec<gtk4::Widget>>,
    f: impl Fn() -> Result<UiValue, String> + 'static,
) -> gtk4::Box {
    let layout = vbox();
    let warning = {
        let w = label("");
        w.add_css_class("error");
        w.set_visible(false);
        layout.append(&w);
        w
    };
    layout.append(body);
    let buttons = hbox();
    layout.append(&buttons);
    let cancel = gtk4::Button::builder().label("Cancel").halign(gtk4::Align::End).build();
    cancel.connect_clicked(|button| {
        let Some(root) = button.root() else {
            return;
        };
        if let Ok(window) = root.downcast::<gtk4::Window>() {
            window.close();
        }
    });
    buttons.append(&cancel);
    let submit =
        gtk4::Button::builder()
            .label("Ok")
            .hexpand(true)
            .halign(gtk4::Align::End)
            .css_classes(["suggested-action"])
            .build();
    buttons.append(&submit);
    submit.set_receives_default(true);
    submit.connect_clicked({
        let state = state.clone();
        move |_button| {
            match f() {
                Ok(r) => {
                    state.finish(id, r);
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
        order.push(cancel.clone().into());
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
    return layout;
}

/// Create and present the window, registering it so the server can close it. Closing
/// the window by any means other than `State::finish`/`State::close` reports
/// `Cancelled`.
fn show_window(state: &Rc<State>, id: u64, title: Title, body: &impl gtk4::glib::object::IsA<gtk4::Widget>) {
    let window =
        gtk4::ApplicationWindow::builder()
            .application(&state.app)
            .title(&format!("Passworth - {}", match title {
                Title::Initialize(x) => format!("Initialize [{}]", x),
                Title::Unlock(x) => format!("Unlock [{}]", x),
                Title::Prompt(x) => format!("Prompt [{}]", x),
            }))
            .resizable(false)
            .build();
    window.init_layer_shell();
    window.set_layer(gtk4_layer_shell::Layer::Overlay);
    window.set_keyboard_mode(gtk4_layer_shell::KeyboardMode::Exclusive);
    let finished = Rc::new(Cell::new(false));
    window.connect_close_request({
        let state = state.clone();
        let finished = finished.clone();
        move |_| {
            if !finished.get() {
                finished.set(true);
                state.windows.borrow_mut().remove(&id);
                state.send(FromUi::Cancelled { id: id });
            }
            gtk4::glib::Propagation::Proceed
        }
    });
    let display = RootExt::display(&window);
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
    {
        let monitors = display.monitors();
        monitors.connect_items_changed({
            let window = window.clone();
            let last_monitor = RefCell::new(window.monitor());
            move |list, position, removed_count, _added_count| {
                for i in position .. position + removed_count {
                    if *last_monitor.borrow() == list.item(i).map(|x| x.dynamic_cast::<Monitor>().unwrap()) {
                        *last_monitor.borrow_mut() = None;
                    }
                }
                if last_monitor.borrow().is_none() {
                    superif!({
                        for i in 0 .. position {
                            break 'found list.item(i).unwrap().dynamic_cast::<Monitor>().unwrap();
                        }
                        for i in position .. list.n_items() {
                            break 'found list.item(i).unwrap().dynamic_cast::<Monitor>().unwrap();
                        }
                    } m = 'found {
                        window.set_monitor(Some(&m));
                        *last_monitor.borrow_mut() = Some(m);
                    });
                }
            }
        });
    }
    state.windows.borrow_mut().insert(id, OpenWindow {
        window: window.upcast(),
        finished: finished,
    });
}

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

fn attach_error(layout: &gtk4::Box, error: Option<String>) {
    if let Some(t) = error {
        let l = label(&t);
        l.add_css_class("error");
        layout.append(&l);
    }
}

fn grid() -> gtk4::Grid {
    return gtk4::Grid::builder()
        .row_spacing(SPACING1)
        .column_spacing(SPACING1)
        .row_homogeneous(true)
        .hexpand(true)
        .build();
}

fn halign_center<T: gtk4::glib::object::IsA<gtk4::Widget>>(w: T) -> T {
    w.set_halign(Align::Center);
    return w;
}

fn halign_end<T: gtk4::glib::object::IsA<gtk4::Widget>>(w: T) -> T {
    w.set_halign(Align::End);
    return w;
}

fn halign_start<T: gtk4::glib::object::IsA<gtk4::Widget>>(w: T) -> T {
    w.set_halign(Align::Start);
    return w;
}

fn hbox() -> gtk4::Box {
    return gtk4::Box::builder().orientation(gtk4::Orientation::Horizontal).spacing(SPACING1).build();
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

fn vbox() -> gtk4::Box {
    return gtk4::Box::builder().orientation(gtk4::Orientation::Vertical).spacing(SPACING1).build();
}
