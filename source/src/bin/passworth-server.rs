#![feature(int_roundings)]

use {
    crate::serverlib::{
        datapath::{
            specific_from_db_path,
            specific_to_db_path,
        },
        dbutil::open_privdb,
        factor::build_factor_tree,
        fg::{
            FgState,
            B2F,
        },
        permission::{
            self,
            build_rule_tree,
            scan_principal,
        },
    },
    aargvark::{
        traits_impls::AargvarkJson,
        vark,
        Aargvark,
    },
    chrono::Utc,
    flowcontrol::shed,
    gtk4::{
        glib::LogLevels,
        prelude::ApplicationExtManual,
    },
    libc::{
        c_void,
    },
    loga::{
        conversion::ResultIgnore,
        ea,
        fatal,
        DebugDisplay,
        Log,
        ResultContext,
    },
    passworth::{
        config,
        generate,
        proto::{
            self,
            ipc_path,
        },
    },
    sequoia_openpgp::{
        cert::CertBuilder,
        packet::{
            key::{
                SecretParts,
                UnspecifiedRole,
            },
            Key,
        },
        parse::{
            stream::DecryptorBuilder,
            Parse,
        },
        policy::StandardPolicy,
        serialize::stream::{
            Message,
            Signer,
        },
        Cert,
    },
    serde_json::json,
    serverlib::{
        dbutil::tx,
        factor::{
            FactorTree,
            FactorTreeVariant,
        },
        fg::{
            self,
            B2FInitialize,
            B2FUnlock,
        },
        privdb,
        pubdb,
    },
    std::{
        cell::RefCell,
        collections::{
            HashMap,
            HashSet,
        },
        env,
        io::Cursor,
        path::PathBuf,
        str::FromStr,
        sync::{
            Arc,
            Mutex,
        },
        time::Duration,
    },
    taskmanager::TaskManager,
    tokio::{
        fs::{
            create_dir_all,
        },
        select,
        spawn,
        sync::{
            broadcast,
            mpsc,
            oneshot,
            Notify,
        },
        task::spawn_blocking,
        time::{
            sleep_until,
            Instant,
        },
    },
    users::UsersCache,
};

pub mod serverlib;

#[derive(Aargvark)]
struct Args {
    config: AargvarkJson<config::Config>,
    /// Log excessive information.
    debug: Option<()>,
    /// Validate config then exit.
    validate: Option<()>,
}

fn bury(root: &mut Option<serde_json::Value>, path: &[String], value: serde_json::Value) {
    if root.is_none() {
        *root = Some(serde_json::Value::Null);
    }
    let mut at = root.as_mut().unwrap();
    for seg in path {
        match &at {
            serde_json::Value::Object(_) => (),
            _ => {
                *at = serde_json::Value::Object(serde_json::Map::new());
            },
        }
        let serde_json::Value::Object(o) = at else {
            panic!();
        };
        let res = o.entry(seg).or_insert(serde_json::Value::Null);
        at = res;
    }
    *at = value;
}

async fn main2() -> Result<(), loga::Error> {
    let args = vark::<Args>();
    if args.validate.is_some() {
        return Ok(());
    }
    let config = match args.config.value {
        config::Config::V1(c) => c,
    };
    let log = Log::new_root(if args.debug.is_some() {
        loga::DEBUG
    } else {
        loga::INFO
    });
    let tm = TaskManager::new();
    for domain in [None, Some("Gtk"), Some("GLib"), Some("Gdk")] {
        gtk4::glib::log_set_handler(domain, LogLevels::all(), true, true, {
            let log = log.clone();
            move |domain, level, text| {
                log.log_with(
                    // Gdk et all log stuff as CRITICAL that's clearly not critical... ignore reported
                    // levels
                    loga::DEBUG,
                    text,
                    ea!(source = "gtk", level = level.dbg_str(), domain = domain.dbg_str()),
                );
            }
        });
    }

    // Data prep + preprocessing
    let users = unsafe {
        UsersCache::with_all_users()
    };
    let rules = build_rule_tree(&users, &config.access)?;
    let root_factor =
        build_factor_tree(
            &HashSet::new(),
            &config.auth_factors.iter().map(|f| (f.id.clone(), f)).collect(),
            &mut HashMap::new(),
            &config.root_factor,
        )?;

    // Start fg thread
    let (fg_tx, mut fg_rx) = mpsc::channel(100);
    tm.critical_task("Foreground interactions", {
        let fg_state = Arc::new(FgState {
            log: log.fork(ea!(sys = "human")),
            last_prompts: Mutex::new(HashMap::new()),
        });
        let work = {
            let tm = tm.clone();
            async move {
                loop {
                    let Some(req) = fg_rx.recv().await else {
                        break;
                    };
                    let req = RefCell::new(Some(req));
                    let tm = RefCell::new(Some(tm.clone()));

                    // Start thread to run gtk, gtk event loop
                    let fg_state = fg_state.clone();
                    spawn_blocking(move || {
                        let app =
                            gtk4::Application::builder()
                                .application_id("x.passworth")
                                .flags(gtk4::gio::ApplicationFlags::FLAGS_NONE)
                                .build();
                        gtk4::gio::prelude::ApplicationExt::connect_activate(&app, move |app| {
                            let app = app.clone();

                            // Hack to work around `connect_activate` being `Fn` instead of `FnOnce`
                            let fg_state = fg_state.clone();
                            let tm = tm.borrow_mut().take().unwrap();
                            let req = req.borrow_mut().take().unwrap();

                            // Start current-thread async task in gtk thread to read queue
                            gtk4::glib::spawn_future_local({
                                let hold = app.hold();
                                let work = async move {
                                    let _hold = hold;
                                    match req {
                                        B2F::Unlock(req, resp) => {
                                            resp.send(fg::do_unlock(fg_state, &app, Arc::new(req)).await).ignore();
                                        },
                                        B2F::Initialize(req, resp) => {
                                            resp
                                                .send(fg::do_initialize(fg_state, &app, Arc::new(req)).await)
                                                .ignore();
                                        },
                                        B2F::Prompt(req, resp) => {
                                            resp.send(fg::do_prompt(fg_state, &app, Arc::new(req)).await).ignore();
                                        },
                                    }
                                };
                                async move {
                                    select!{
                                        _ = work =>(),
                                        _ = tm.until_terminate() =>()
                                    };
                                }
                            });
                        });
                        gtk4::prelude::ApplicationExtManual::run_with_args(&app, &[] as &[String]);
                    }).await.unwrap();
                }
            }
        };
        let tm = tm.clone();
        async move {
            select!{
                _ = work =>(),
                _ = tm.until_terminate() =>()
            };
            return Ok(());
        }
    });

    // Prep state for everything else
    struct TokenState {
        token: Option<String>,
        wait_sub: Option<broadcast::Sender<String>>,
    }

    struct State {
        pubdb_path: PathBuf,
        privdb_path: PathBuf,
        root_factor: Arc<FactorTree>,
        token: Mutex<TokenState>,
        fg_tx: mpsc::Sender<B2F>,
        last_activity: Mutex<Instant>,
        lock_timeout: u64,
    }

    let data_path = match args.config.source {
        aargvark::traits_impls::Source::Stdin => {
            env::current_dir().context("Couldn't determine working directory")?
        },
        aargvark::traits_impls::Source::File(f) => {
            f.parent().unwrap().join(&config.data_path)
        },
    };
    create_dir_all(&data_path)
        .await
        .context_with("Error creating data path", ea!(path = data_path.to_string_lossy()))?;
    let pubdb_path = data_path.join("pub.sqlite");
    let state = Arc::new(State {
        privdb_path: data_path.join("priv.sqlcipher"),
        pubdb_path: pubdb_path.clone(),
        root_factor: root_factor.clone(),
        fg_tx: fg_tx,
        token: Mutex::new(TokenState {
            token: None,
            wait_sub: None,
        }),
        last_activity: Mutex::new(Instant::now()),
        lock_timeout: config.lock_timeout,
    });

    // Initialize db, process config changes
    let mut pubdbc = rusqlite::Connection::open(&pubdb_path).unwrap();
    pubdb::migrate(
        &mut pubdbc,
    ).context_with("Error setting up pub database", ea!(path = pubdb_path.to_string_lossy()))?;
    shed!{
        'priv_init_done _;
        let mut prev_state = HashMap::new();
        for t in pubdb::factor_list(&mut pubdbc)? {
            prev_state.insert(t.id, t.state);
        }
        if let Some(previous_config) = pubdb::config_get(&mut pubdbc)? {
            let previous_config = match previous_config {
                config::Config::V1(config) => config,
            };

            // Previous config existed
            let prev_root_factor =
                build_factor_tree(
                    &HashSet::new(),
                    &previous_config.auth_factors.iter().map(|f| (f.id.clone(), f)).collect(),
                    &mut HashMap::new(),
                    &previous_config.root_factor,
                )?;

            // Diff with old to check what tokens/state changed, get list of still-active
            // factors
            let factor_active: HashSet<String>;
            let mut factor_token_changed = HashSet::new();
            let mut factor_state_changed = HashSet::new();
            {
                let mut stack = vec![(&root_factor, Some(&prev_root_factor), true)];
                let mut seen = HashSet::new();
                while let Some((new, old, descending)) = stack.pop() {
                    if !seen.insert(new.id.clone()) {
                        continue;
                    }
                    let old_variant = old.map(|x| &x.variant);
                    match &new.variant {
                        FactorTreeVariant::And(children) => {
                            if descending {
                                stack.push((new, old, false));
                                let mut old_lookup = HashMap::new();
                                if let Some(FactorTreeVariant::Or(old_children)) = old_variant {
                                    for old_child in old_children {
                                        old_lookup.insert(old_child.id.clone(), old_child);
                                    }
                                }
                                for child in children {
                                    stack.push((child, old_lookup.get(&child.id).map(|x| *x), true));
                                }
                            } else {
                                let mut changed = false;
                                for child in children {
                                    if factor_token_changed.contains(&child.id) {
                                        changed = true;
                                    }
                                }
                                if changed {
                                    factor_token_changed.insert(new.id.clone());
                                }
                            }
                        },
                        FactorTreeVariant::Or(children) => {
                            if descending {
                                stack.push((new, old, false));
                                let mut old_lookup = HashMap::new();
                                if let Some(FactorTreeVariant::Or(old_children)) = old_variant {
                                    for old_child in old_children {
                                        old_lookup.insert(old_child.id.clone(), old_child);
                                    }
                                }
                                for child in children {
                                    stack.push((child, old_lookup.get(&child.id).map(|x| *x), true));
                                }
                            } else {
                                if matches!(old_variant, Some(FactorTreeVariant::Or(_))) {
                                    // nop
                                } else {
                                    factor_token_changed.insert(new.id.clone());
                                }
                                for child in children {
                                    if factor_token_changed.contains(&child.id) {
                                        factor_state_changed.insert(new.id.clone());
                                        break;
                                    }
                                }
                            }
                        },
                        FactorTreeVariant::Password => {
                            if matches!(old_variant, Some(FactorTreeVariant::Password)) {
                                // nop
                            } else {
                                factor_token_changed.insert(new.id.clone());
                            }
                        },
                        FactorTreeVariant::Smartcards(config) => {
                            let mut lookup_old_children = HashSet::new();
                            if let Some(FactorTreeVariant::Smartcards(old_config)) = old_variant {
                                for child in &old_config.smartcards {
                                    lookup_old_children.insert(child.fingerprint.clone());
                                }
                            } else {
                                factor_token_changed.insert(new.id.clone());
                            }
                            for child in &config.smartcards {
                                if !lookup_old_children.contains(&child.fingerprint) {
                                    factor_state_changed.insert(new.id.clone());
                                    break;
                                }
                            }
                        },
                        FactorTreeVariant::RecoveryPhrase => {
                            if matches!(old_variant, Some(FactorTreeVariant::RecoveryPhrase)) {
                                // nop
                            } else {
                                factor_token_changed.insert(new.id.clone());
                            }
                        },
                    }
                }
                factor_active = seen;
            }

            // Skip if nothing changed
            let root_token_changed = factor_token_changed.contains(&root_factor.id);
            if factor_state_changed.is_empty() && root_token_changed {
                break 'priv_init_done;
            }
            let mut remove_state = prev_state.keys().cloned().collect::<Vec<_>>();
            remove_state.retain(|x| !factor_active.contains(x));

            // Otherwise first unlock
            let unlock_result;
            {
                let (resp_tx, resp_rx) = oneshot::channel();
                state.fg_tx.send(B2F::Unlock(B2FUnlock {
                    privdb_path: state.privdb_path.clone(),
                    root_factor: prev_root_factor.clone(),
                    state: prev_state.clone(),
                }, resp_tx)).await.ignore();
                unlock_result =
                    resp_rx
                        .await?
                        .context("Error doing fg unlock")?
                        .context("Config update unlock aborted by user")?;
            }

            // Continue with init
            let (resp_tx, resp_rx) = oneshot::channel();
            state.fg_tx.send(B2F::Initialize(B2FInitialize {
                privdbc: None,
                root_factor: root_factor.clone(),
                tokens_changed: factor_token_changed,
                prev_tokens: unlock_result.tokens,
                state_changed: factor_state_changed,
                prev_state: prev_state,
                prev_root_factor: Some(prev_root_factor),
            }, resp_tx)).await.ignore();
            let init_result =
                resp_rx
                    .await?
                    .context("Error doing fg initialize")?
                    .context("Credential initialization aborted by user")?;

            // Store the new config and tokens
            tx(pubdbc, move |txn| {
                for k in &remove_state {
                    eprintln!("CHANGE remove factor {}", k);
                    if !pubdb::factor_delete(txn, k)
                        .context_with("Error removing obsolete factor data", ea!(factor = k))?
                        .is_some() {
                        panic!();
                    }
                }
                for (k, v) in &init_result.store_state {
                    eprintln!("CHANGE add factor {}", k);
                    pubdb::factor_add(txn, &k, &v).context_with("Error storing new factor data", ea!(factor = k))?;
                }
                pubdb::config_set(txn, &config::Config::V1(config))?;
                if root_token_changed {
                    let Some(root_token) = init_result.root_token else {
                        panic!();
                    };
                    let root_token = root_token.as_bytes();
                    let res = unsafe {
                        libsqlite3_sys::sqlite3_rekey(
                            unlock_result.privdbc.handle(),
                            root_token.as_ptr() as *const c_void,
                            root_token.len() as i32,
                        )
                    };
                    if res != 0 {
                        return Err(loga::err_with("Sqlcipher rekey operation exited with code", ea!(code = res)));
                    }
                }
                return Ok(());
            }).await.context("Error committing new unlock credentials")?;
        }
        else {
            let all_factors = config.auth_factors.iter().map(|x| x.id.clone()).collect::<HashSet<_>>();
            let (resp_tx, resp_rx) = oneshot::channel();
            state.fg_tx.send(B2F::Initialize(B2FInitialize {
                privdbc: None,
                root_factor: root_factor.clone(),
                tokens_changed: all_factors.clone(),
                prev_tokens: HashMap::new(),
                state_changed: all_factors.clone(),
                prev_state: HashMap::new(),
                prev_root_factor: None,
            }, resp_tx)).await.ignore();
            let init_result =
                resp_rx
                    .await?
                    .context("Error doing fg initialize")?
                    .context("Credential initialization aborted by user")?;

            // Store the new config and tokens
            tx(pubdbc, move |txn| {
                for (k, v) in &init_result.store_state {
                    eprintln!("NEW add factor {}", k);
                    pubdb::factor_add(txn, &k, &v).context_with("Error storing new factor data", ea!(factor = k))?;
                }
                pubdb::config_set(txn, &config::Config::V1(config))?;
                return Ok(());
            }).await.context("Error committing new unlock credentials")?;
        }
    };

    // Start command server
    let activity = Arc::new(Notify::new());
    let mut ipc_server = proto::msg::Server::new(ipc_path()).await.map_err(loga::err)?;
    tm.critical_task("Command processing", {
        async fn get_privdb(state: &State) -> Result<rusqlite::Connection, loga::Error> {
            enum Invert {
                Ready {
                    token: String,
                },
                Waiting {
                    token_rx: broadcast::Receiver<String>,
                },
                Missing {
                    token_tx: broadcast::Sender<String>,
                },
            }

            let privdbc = match {
                let mut token = state.token.lock().unwrap();
                match &token.token {
                    Some(t) => Invert::Ready { token: t.clone() },
                    None => {
                        match &token.wait_sub {
                            Some(s) => {
                                let token_rx = s.subscribe();
                                Invert::Waiting { token_rx: token_rx }
                            },
                            None => {
                                let (token_tx, _) = broadcast::channel(1);
                                token.wait_sub = Some(token_tx.clone());
                                Invert::Missing { token_tx: token_tx }
                            },
                        }
                    },
                }
            } {
                Invert::Ready { token } => {
                    open_privdb(&state.privdb_path, &token)?
                },
                Invert::Waiting { mut token_rx } => {
                    open_privdb(&state.privdb_path, &token_rx.recv().await?)?
                },
                Invert::Missing { token_tx } => {
                    // Unlock
                    let mut pubdbc = rusqlite::Connection::open(&state.pubdb_path).unwrap();
                    let mut factor_state = HashMap::new();
                    for t in pubdb::factor_list(&mut pubdbc)? {
                        factor_state.insert(t.id, t.state);
                    }
                    let (fg_tx, fg_rx) = oneshot::channel();
                    state.fg_tx.send(B2F::Unlock(B2FUnlock {
                        privdb_path: state.privdb_path.clone(),
                        root_factor: state.root_factor.clone(),
                        state: factor_state,
                    }, fg_tx)).await.ignore();
                    let res = fg_rx.await?.context("Error during fg unlock")?.context("User closed unlock window")?;

                    // Update shared token + return
                    let mut token = state.token.lock().unwrap();
                    token.wait_sub = None;
                    token.token = Some(res.root_token.clone());
                    token_tx.send(res.root_token.clone()).ignore();
                    res.privdbc
                },
            };
            return Ok(privdbc);
        }

        let tm = tm.clone();
        let log = log.clone();
        let rules = rules.clone();
        let state = state.clone();
        let activity = activity.clone();
        async move {
            loop {
                let conn = select!{
                    c = ipc_server.accept() => c,
                    _ = tm.until_terminate() => {
                        break;
                    }
                };
                let log = log.clone();
                let rules = rules.clone();
                let state = state.clone();
                let activity = activity.clone();
                let mut conn = match conn.map_err(loga::err) {
                    Ok(c) => c,
                    Err(e) => {
                        log.log_err(loga::DEBUG, e.context("Error receiving ipc connection"));
                        break;
                    },
                };
                spawn(async move {
                    match async {
                        let peer = conn.0.peer_cred()?;
                        let pid = peer.pid().context("OS didn't provide PID for peer")?;
                        let peer_meta = scan_principal(&log, pid).await?;

                        // Helpers for command processing
                        let set = |txn: &mut rusqlite::Transaction, pairs: Vec<(Vec<String>, Option<serde_json::Value>)>| {
                            let now = Utc::now();
                            for (mut path, value) in pairs {
                                // Clear out everything above and below that would be shaded by this
                                for row in privdb::values_get_above_below(txn, &specific_to_db_path(&path), i64::MAX)? {
                                    privdb::values_insert(txn, now, &row.path, None)?;
                                }

                                // Add the new data
                                let mut stack = vec![(None as Option<String>, value, true)];
                                while let Some((seg, at, descending)) = stack.pop() {
                                    if descending {
                                        if let Some(seg) = &seg {
                                            path.push(seg.clone());
                                        }
                                        match &at {
                                            Some(serde_json::Value::Object(o)) => {
                                                for (k, v) in o {
                                                    stack.push((Some(k.to_string()), Some(v.clone()), true));
                                                }
                                            },
                                            _ => {
                                                privdb::values_insert(
                                                    txn,
                                                    now,
                                                    &specific_to_db_path(&path),
                                                    at
                                                        .as_ref()
                                                        .map(|at| serde_json::to_string(&at).unwrap())
                                                        .as_ref()
                                                        .map(|x| x.as_str()),
                                                )?;
                                            },
                                        }
                                        stack.push((seg, at, false));
                                    } else {
                                        if seg.is_some() {
                                            path.pop();
                                        }
                                    }
                                }
                            }
                            return Ok(()) as Result<_, loga::Error>;
                        };
                        let get =
                            |txn: &mut rusqlite::Transaction, path: &Vec<String>, at: Option<i64>| ->
                                Result<Option<serde_json::Value>, loga::Error> {
                                let mut root = None;
                                for row in privdb::values_get(
                                    txn,
                                    &specific_to_db_path(&path),
                                    at.unwrap_or(i64::MAX),
                                )? {
                                    let Some(row_data) = row.data else {
                                        continue;
                                    };
                                    bury(
                                        &mut root,
                                        &specific_from_db_path(&row.path).split_off(path.len()),
                                        serde_json::from_str::<serde_json::Value>(&row_data).unwrap(),
                                    );
                                }
                                return Ok(root);
                            };

                        // Process request
                        while let Some(req) = conn.recv_req().await.map_err(loga::err)? {
                            fn resp_unauthorized() -> Result<proto::msg::ServerResp, loga::Error> {
                                return Err(loga::err("Unauthorized"));
                            }

                            let resp;
                            match async {
                                let resp;
                                match req {
                                    proto::msg::ServerReq::Unlock(rr, _req) => {
                                        if !permission::permit(
                                            state.fg_tx.clone(),
                                            &rules,
                                            &peer_meta,
                                            &[vec!["".to_string()]],
                                        )
                                            .await?
                                            .lock {
                                            return resp_unauthorized();
                                        }
                                        get_privdb(&state).await?;
                                        activity.notify_one();
                                        resp = rr(());
                                    },
                                    proto::msg::ServerReq::Lock(rr, _req) => {
                                        if !permission::permit(
                                            state.fg_tx.clone(),
                                            &rules,
                                            &peer_meta,
                                            &[vec!["".to_string()]],
                                        )
                                            .await?
                                            .lock {
                                            return resp_unauthorized();
                                        }
                                        state.token.lock().unwrap().token = None;
                                        resp = rr(());
                                    },
                                    proto::msg::ServerReq::Get(rr, req) => {
                                        if !permission::permit(state.fg_tx.clone(), &rules, &peer_meta, &req.paths)
                                            .await?
                                            .read {
                                            return resp_unauthorized();
                                        }
                                        let tree = tx(get_privdb(&state).await?, move |txn| {
                                            let mut root = None;
                                            for path in &req.paths {
                                                let Some(data) = get(txn, path, req.at)? else {
                                                    continue;
                                                };
                                                bury(&mut root, &path, data);
                                            }
                                            return Ok(root);
                                        }).await?;
                                        activity.notify_one();
                                        resp = rr(serde_json::to_value(&tree).unwrap());
                                    },
                                    proto::msg::ServerReq::Set(rr, req) => {
                                        if !permission::permit(
                                            state.fg_tx.clone(),
                                            &rules,
                                            &peer_meta,
                                            &req.0.iter().map(|(path, _)| path.clone()).collect::<Vec<_>>(),
                                        )
                                            .await?
                                            .write {
                                            return resp_unauthorized();
                                        }
                                        tx(get_privdb(&state).await?, move |txn| {
                                            set(txn, req.0.into_iter().map(|(k, v)| (k, Some(v))).collect())?;
                                            return Ok(());
                                        }).await?;
                                        activity.notify_one();
                                        resp = rr(());
                                    },
                                    proto::msg::ServerReq::Move(rr, req) => {
                                        if !permission::permit(
                                            state.fg_tx.clone(),
                                            &rules,
                                            &peer_meta,
                                            &[req.from.clone(), req.to.clone()],
                                        )
                                            .await?
                                            .write {
                                            return resp_unauthorized();
                                        }
                                        tx(get_privdb(&state).await?, move |txn| {
                                            if get(txn, &req.from, None)?.is_some() && !req.overwrite {
                                                return Err(
                                                    loga::err(
                                                        "Attempt to move over existing value with overwrite off",
                                                    ),
                                                );
                                            }
                                            let data = get(txn, &req.from, None)?;
                                            set(txn, vec![(req.from, None), (req.to, data)])?;
                                            return Ok(());
                                        }).await?;
                                        activity.notify_one();
                                        resp = rr(());
                                    },
                                    proto::msg::ServerReq::Generate(rr, req) => {
                                        if !permission::permit(
                                            state.fg_tx.clone(),
                                            &rules,
                                            &peer_meta,
                                            &[req.path.clone()],
                                        )
                                            .await?
                                            .write {
                                            return resp_unauthorized();
                                        }
                                        let db_resp = tx(get_privdb(&state).await?, move |txn| {
                                            if get(txn, &req.path, None)?.is_some() && !req.overwrite {
                                                return Err(
                                                    loga::err("Destructive command but flag to allow not specified"),
                                                );
                                            }
                                            let res_data;
                                            let data;
                                            match req.variant {
                                                passworth::proto::C2SGenerateVariant::Bytes { length } => {
                                                    data =
                                                        serde_json::to_value(&generate::gen_bytes(length)).unwrap();
                                                    res_data = "".to_string();
                                                },
                                                passworth::proto::C2SGenerateVariant::SafeAlphanumeric { length } => {
                                                    data =
                                                        serde_json::to_value(
                                                            generate::gen_safe_alphanum(length),
                                                        ).unwrap();
                                                    res_data = "".to_string();
                                                },
                                                passworth::proto::C2SGenerateVariant::Alphanumeric { length } => {
                                                    data =
                                                        serde_json::to_value(
                                                            generate::gen_alphanum(length),
                                                        ).unwrap();
                                                    res_data = "".to_string();
                                                },
                                                passworth
                                                ::proto
                                                ::C2SGenerateVariant
                                                ::AlphanumericSymbols {
                                                    length,
                                                } => {
                                                    data =
                                                        serde_json::to_value(
                                                            generate::gen_alphanum_symbols(length),
                                                        ).unwrap();
                                                    res_data = "".to_string();
                                                },
                                                passworth::proto::C2SGenerateVariant::Pgp => {
                                                    let (cert, _) =
                                                        CertBuilder::new()
                                                            .set_cipher_suite(
                                                                sequoia_openpgp::cert::CipherSuite::Cv25519,
                                                            )
                                                            .add_signing_subkey()
                                                            .add_subkey(
                                                                sequoia_openpgp::types::KeyFlags::empty()
                                                                    .set_transport_encryption()
                                                                    .set_storage_encryption(),
                                                                None,
                                                                None,
                                                            )
                                                            .generate()
                                                            .map_err(|e| loga::err(e.to_string()))
                                                            .context("Error generating pgp cert")?;
                                                    {
                                                        let mut bytes = Vec::new();
                                                        sequoia_openpgp::serialize::Serialize::serialize(
                                                            &cert.armored(),
                                                            &mut bytes,
                                                        )
                                                            .map_err(|e| loga::err(e.to_string()))
                                                            .context("Error serializing public key")?;
                                                        res_data = unsafe {
                                                            String::from_utf8_unchecked(bytes)
                                                        };
                                                    }
                                                    {
                                                        let mut w =
                                                            sequoia_openpgp::armor::Writer::with_headers(
                                                                vec![],
                                                                sequoia_openpgp::armor::Kind::SecretKey,
                                                                cert
                                                                    .armor_headers()
                                                                    .iter()
                                                                    .map(|value| ("Comment", value.as_str()))
                                                                    .collect::<Vec<_>>(),
                                                            )?;
                                                        sequoia_openpgp::serialize::Serialize::serialize(
                                                            &cert.as_tsk(),
                                                            &mut w,
                                                        )
                                                            .map_err(|e| loga::err(e.to_string()))
                                                            .context("Error serializing private key")?;
                                                        data = serde_json::to_value(&w.finalize()?).unwrap();
                                                    }
                                                },
                                            };
                                            set(txn, vec![(req.path, Some(data))])?;
                                            return Ok(res_data);
                                        }).await?;
                                        activity.notify_one();
                                        resp = rr(db_resp);
                                    },
                                    proto::msg::ServerReq::PgpSign(rr, req) => {
                                        if !permission::permit(
                                            state.fg_tx.clone(),
                                            &rules,
                                            &peer_meta,
                                            &[req.key.clone()],
                                        )
                                            .await?
                                            .derive {
                                            return resp_unauthorized();
                                        }
                                        let db_key = tx(get_privdb(&state).await?, move |txn| {
                                            return Ok(get(txn, &req.key, None)?);
                                        }).await?;
                                        let Some(serde_json::Value::String(key)) = db_key else {
                                            return Err(loga::err("No value at path or value is not a string"));
                                        };
                                        let mut signed = vec![];
                                        let mut signer =
                                            Signer::with_template(
                                                Message::new(&mut signed),
                                                Cert::from_str(&key)
                                                    .map_err(loga::err)
                                                    .context("Error loading data at path as pgp cert")?
                                                    .keys()
                                                    .secret()
                                                    .with_policy(&StandardPolicy::new(), None)
                                                    .supported()
                                                    .for_signing()
                                                    .nth(0)
                                                    .unwrap()
                                                    .key()
                                                    .clone()
                                                    .into_keypair()
                                                    .map_err(loga::err)
                                                    .context("Error converting pgp cert at path into pgp keypair")?,
                                                sequoia_openpgp::packet::signature::SignatureBuilder::new(
                                                    sequoia_openpgp::types::SignatureType::Text,
                                                ),
                                            )
                                                .detached()
                                                .build()
                                                .map_err(loga::err)
                                                .context("Error building signer")?;
                                        std::io::copy(
                                            &mut Cursor::new(req.data),
                                            &mut signer,
                                        ).context("Error signing data")?;
                                        signer.finalize().map_err(loga::err).context("Error finishing signature")?;
                                        activity.notify_one();
                                        resp = rr(signed);
                                    },
                                    proto::msg::ServerReq::PgpDecrypt(rr, req) => {
                                        if !permission::permit(
                                            state.fg_tx.clone(),
                                            &rules,
                                            &peer_meta,
                                            &[req.key.clone()],
                                        )
                                            .await?
                                            .derive {
                                            return resp_unauthorized();
                                        }
                                        let db_key = tx(get_privdb(&state).await?, move |txn| {
                                            return Ok(get(txn, &req.key, None)?);
                                        }).await?;
                                        let Some(serde_json::Value::String(key)) = db_key else {
                                            return Err(loga::err("No value at path or value is not a string"));
                                        };
                                        let mut decrypted = vec![];

                                        struct Helper(Cert);

                                        impl Helper {
                                            fn secret_key(&self) -> Key<SecretParts, UnspecifiedRole> {
                                                return self
                                                    .0
                                                    .keys()
                                                    .secret()
                                                    .with_policy(&StandardPolicy::new(), None)
                                                    .supported()
                                                    .for_storage_encryption()
                                                    .nth(0)
                                                    .unwrap()
                                                    .key()
                                                    .clone();
                                            }
                                        }

                                        impl sequoia_openpgp::parse::stream::VerificationHelper for Helper {
                                            fn get_certs(
                                                &mut self,
                                                ids: &[sequoia_openpgp::KeyHandle],
                                            ) -> sequoia_openpgp::Result<Vec<Cert>> {
                                                let own_id = self.secret_key().key_handle();
                                                for id in ids {
                                                    if id.aliases(&own_id) {
                                                        return Ok(vec![self.0.clone()]);
                                                    }
                                                }
                                                return Ok(vec![]);
                                            }

                                            fn check(
                                                &mut self,
                                                _structure: sequoia_openpgp::parse::stream::MessageStructure,
                                            ) -> sequoia_openpgp::Result<()> {
                                                return Ok(());
                                            }
                                        }

                                        impl sequoia_openpgp::parse::stream::DecryptionHelper for Helper {
                                            fn decrypt<
                                                D,
                                            >(
                                                &mut self,
                                                pkesks: &[sequoia_openpgp::packet::PKESK],
                                                _skesks: &[sequoia_openpgp::packet::SKESK],
                                                sym_algo: Option<sequoia_openpgp::types::SymmetricAlgorithm>,
                                                mut decrypt: D,
                                            ) -> sequoia_openpgp::Result<Option<sequoia_openpgp::Fingerprint>>
                                            where
                                                D:
                                                    FnMut(
                                                        sequoia_openpgp::types::SymmetricAlgorithm,
                                                        &sequoia_openpgp::crypto::SessionKey,
                                                    ) -> bool {
                                                let mut keypair = self.secret_key().into_keypair()?;
                                                for pkesk in pkesks {
                                                    let Some((sym_algo, sk)) =
                                                        pkesk.decrypt(&mut keypair, sym_algo) else {
                                                            continue;
                                                        };
                                                    if decrypt(sym_algo, &sk) {
                                                        return Ok(Some(keypair.public().fingerprint()));
                                                    }
                                                }
                                                return Ok(None);
                                            }
                                        }

                                        let policy = StandardPolicy::new();
                                        let mut decryptor =
                                            DecryptorBuilder::from_bytes(&req.data)
                                                .map_err(loga::err)
                                                .context("Error creating decryptor from data to decrypt")?
                                                .with_policy(
                                                    &policy,
                                                    None,
                                                    Helper(
                                                        Cert::from_str(&key)
                                                            .map_err(loga::err)
                                                            .context("Error creating pgp cert from data at path")?,
                                                    ),
                                                )
                                                .map_err(loga::err)
                                                .context("Error matching cert to data to decrypt")?;
                                        std::io::copy(&mut decryptor, &mut Cursor::new(&mut decrypted))
                                            .map_err(loga::err)
                                            .context("Error decrypting data")?;
                                        activity.notify_one();
                                        resp = rr(decrypted);
                                    },
                                    proto::msg::ServerReq::GetRevisions(rr, req) => {
                                        if !permission::permit(state.fg_tx.clone(), &rules, &peer_meta, &req.paths)
                                            .await?
                                            .read {
                                            return resp_unauthorized();
                                        }
                                        let mut privdbc = get_privdb(&state).await?;
                                        let db_resp = spawn_blocking(move || {
                                            let mut root = Some(serde_json::Value::Null);
                                            for path in req.paths {
                                                for row in privdb::values_get(
                                                    &mut privdbc,
                                                    &specific_to_db_path(&path),
                                                    req.at.map(|x| x as i64).unwrap_or(i64::MAX),
                                                )? {
                                                    if row.data.is_none() {
                                                        continue;
                                                    }
                                                    bury(&mut root, &specific_from_db_path(&row.path), json!({
                                                        "rev_id": row.rev_id,
                                                        "rev_stamp": row.rev_stamp.to_rfc3339(),
                                                    }));
                                                }
                                            }
                                            return Ok(root.unwrap()) as Result<_, loga::Error>;
                                        }).await??;
                                        activity.notify_one();
                                        resp = rr(db_resp);
                                    },
                                    proto::msg::ServerReq::Revert(rr, req) => {
                                        if !permission::permit(state.fg_tx.clone(), &rules, &peer_meta, &req.paths)
                                            .await?
                                            .write {
                                            return resp_unauthorized();
                                        }
                                        tx(get_privdb(&state).await?, move |txn| {
                                            for path in req.paths {
                                                let data = get(txn, &path, Some(req.at))?;
                                                set(txn, vec![(path, data)])?;
                                            }
                                            return Ok(()) as Result<_, loga::Error>;
                                        }).await?;
                                        activity.notify_one();
                                        resp = rr(());
                                    },
                                }
                                return Ok(resp);
                            }.await {
                                Ok(r) => {
                                    resp = r;
                                },
                                Err(e) => {
                                    log.log_err(loga::WARN, e.context("Error processing request"));
                                    resp = proto::msg::ServerResp::err("Encountered error processing request");
                                },
                            };
                            conn.send_resp(resp).await.map_err(loga::err)?;
                        }
                        return Ok(()) as Result<_, loga::Error>;
                    }.await {
                        Ok(_) => { },
                        Err(e) => {
                            log.log_err(loga::WARN, e.context("Error during connection setup"));
                        },
                    }
                });
            }
            return Ok(());
        }
    });

    // Timeout-locks
    tm.critical_task("Timeouts", {
        let tm = tm.clone();
        let state = state.clone();
        let log = log.fork(ea!(sys = "timeouts"));
        async move {
            let mut next = None;
            loop {
                select!{
                    _ = tm.until_terminate() => {
                        return Ok(());
                    }
                    _ = activity.notified() => {
                        next = Some(*state.last_activity.lock().unwrap() + Duration::from_secs(state.lock_timeout));
                    }
                    _ = async {
                        sleep_until(next.take().unwrap()).await
                    },
                    if next.is_some() => {
                        log.log(loga::DEBUG, "Activity timeout, locking");
                        state.token.lock().unwrap().token = None;
                    }
                }
            }
        }
    });

    // Start bg tasks (timeouts mainly) Wait forever
    tm.join(&log).await?;
    return Ok(());
}

#[tokio::main]
async fn main() {
    match main2().await {
        Ok(_) => { },
        Err(e) => {
            fatal(e);
        },
    }
}
