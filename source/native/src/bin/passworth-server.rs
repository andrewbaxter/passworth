pub mod serverlib;

use {
    aargvark::{
        Aargvark,
        traits_impls::AargvarkJson,
        vark,
    },
    chrono::Utc,
    crate::serverlib::{
        dbutil::open_privdb,
        factor::build_factor_tree,
        fg::{
            B2F,
            FgState,
        },
        permission::{
            build_rule_tree,
            scan_principal,
            self,
        },
    },
    flowcontrol::{
        exenum,
        shed,
    },
    libc::c_void,
    loga::{
        DebugDisplay,
        ErrContext,
        Log,
        ResultContext,
        conversion::ResultIgnore,
        ea,
        fatal,
    },
    passworth::{
        datapath::SpecificPath,
        ipc,
        utils::to_b32,
    },
    passworth_native::{
        config,
        crypto::{
            TokenScheme,
            pgp_from_armor,
        },
        generate,
    },
    passworth_shared_native::proto::ipc_path,
    sequoia_openpgp::{
        Cert,
        cert::CertBuilder,
        packet::{
            Key,
            key::{
                SecretParts,
                UnspecifiedRole,
            },
        },
        parse::{
            Parse,
            stream::DecryptorBuilder,
        },
        policy::StandardPolicy,
        serialize::{
            SerializeInto,
            stream::{
                Message,
                Signer,
            },
        },
    },
    serde_json::json,
    serverlib::{
        dbutil::tx,
        factor::{
            FactorTree,
            FactorTreeVariant,
        },
        fg::{
            B2FInitialize,
            B2FUnlock,
            self,
        },
        pidfd::{
            Inode,
            pidfd,
        },
        privdb,
        pubdb,
        uiclient::UiSpawnConfig,
    },
    std::{
        collections::{
            HashMap,
            HashSet,
        },
        env,
        fs::Permissions,
        io::{
            Cursor,
            Write,
        },
        os::{
            fd::OwnedFd,
            unix::fs::PermissionsExt,
        },
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
            self,
        },
        io::unix::AsyncFdReadyGuard,
        select,
        spawn,
        sync::{
            Notify,
            oneshot,
        },
        task::spawn_blocking,
        time::{
            Instant,
            sleep_until,
        },
    },
    users::{
        Users,
        UsersCache,
        os::unix::UserExt,
    },
};

#[derive(Aargvark)]
struct Args {
    config: AargvarkJson<config::latest::Config>,
    /// Log excessive information.
    debug: Option<()>,
    /// Validate config then exit.
    validate: Option<()>,
}

fn bury(root: &mut serde_json::Value, path: &SpecificPath, value: serde_json::Value) {
    let mut at = root;
    for seg in &path.0 {
        match &at {
            serde_json::Value::Object(_) => (),
            _ => {
                *at = serde_json::Value::Object(serde_json::Map::new());
            },
        }
        let o = exenum!(at, serde_json:: Value:: Object(o) => o).unwrap();
        let next = o.entry(seg).or_insert(serde_json::Value::Null);
        at = next;
    }
    *at = value;
}

fn parse_row_data(data: &str) -> Result<serde_json::Value, loga::Error> {
    return Ok(
        serde_json::from_str::<serde_json::Value>(data).context("Corrupt (non-JSON) value found in database")?,
    );
}

fn parse_row_path(path: &str) -> Result<SpecificPath, loga::Error> {
    return Ok(
        SpecificPath::from_str(path).map_err(loga::err).context("Corrupt (unparsable) path found in database")?,
    );
}

/// After leaf/explicit changes have been recorded, propagate them up the tree: an
/// `and` whose child token changed has a changed token itself, an `or` whose child
/// token changed needs its state regenerated. Returns whether the node's token
/// changed.
fn propagate_changes(
    node: &Arc<FactorTree>,
    token_changed: &mut HashSet<String>,
    state_changed: &mut HashSet<String>,
) -> bool {
    match &node.variant {
        FactorTreeVariant::And(children) => {
            let mut any = false;
            for child in children {
                if propagate_changes(child, token_changed, state_changed) {
                    any = true;
                }
            }
            if any {
                token_changed.insert(node.id.clone());
            }
        },
        FactorTreeVariant::Or(children) => {
            let mut any = false;
            for child in children {
                if propagate_changes(child, token_changed, state_changed) {
                    any = true;
                }
            }
            if any {
                state_changed.insert(node.id.clone());
            }
        },
        FactorTreeVariant::Password | FactorTreeVariant::RecoveryPhrase | FactorTreeVariant::Smartcards(_) => { },
    }
    return token_changed.contains(&node.id);
}

/// Which factors' tokens are different between the legacy and current schemes (see
/// `config::UnlockConfig`).
fn legacy_scheme_token_changes(node: &Arc<FactorTree>, token_changed: &mut HashSet<String>) {
    match &node.variant {
        FactorTreeVariant::And(children) => {
            token_changed.insert(node.id.clone());
            for child in children {
                legacy_scheme_token_changes(child, token_changed);
            }
        },
        FactorTreeVariant::Or(children) => {
            for child in children {
                legacy_scheme_token_changes(child, token_changed);
            }
        },
        FactorTreeVariant::Password | FactorTreeVariant::RecoveryPhrase => {
            token_changed.insert(node.id.clone());
        },
        FactorTreeVariant::Smartcards(_) => { },
    }
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

async fn main2() -> Result<(), loga::Error> {
    let args = vark::<Args>();
    if args.validate.is_some() {
        return Ok(());
    }
    let config = args.config.value;
    let log = Log::new_root(if args.debug.is_some() {
        loga::DEBUG
    } else {
        loga::INFO
    });

    // This process holds every secret while unlocked; keep it out of core dumps (and
    // off limits to same-uid ptrace). No memory cost.
    if unsafe {
        libc::prctl(libc::PR_SET_DUMPABLE, 0)
    } != 0 {
        return Err(std::io::Error::last_os_error().context("Error marking process non-dumpable"));
    }

    // Tags are keyed by pidfd inode. Before Linux 6.9 pidfds were anonymous inodes
    // that all share one inode number, which would make every tagged process
    // indistinguishable.
    {
        let (self_ino, _self_fd) =
            pidfd(std::process::id() as i32).await.context("Error opening pidfd for self")?;
        let (init_ino, _init_fd) = pidfd(1).await.context("Error opening pidfd for pid 1")?;
        if self_ino == init_ino {
            return Err(
                loga::err(
                    "This kernel does not give pidfds unique inodes (requires Linux 6.9 or newer); refusing to start since process tags would be unreliable",
                ),
            );
        }
    }

    let tm = TaskManager::new();

    // Data prep + preprocessing
    let users = unsafe {
        UsersCache::with_all_users()
    };
    let rules = build_rule_tree(&users, &config.access)?;
    let ui_config = {
        let ui = config.ui.clone().unwrap_or_default();
        let binary = match ui.binary {
            Some(b) => b,
            None => env::current_exe()
                .context("Couldn't determine own executable path to locate passworth-ui")?
                .parent()
                .context("Own executable path has no parent directory")?
                .join("passworth-ui"),
        };
        let run_as = match ui.user {
            Some(u) => {
                let user = match &u {
                    config::latest::UserGroupId::Id(i) => users.get_user_by_uid(*i),
                    config::latest::UserGroupId::Name(n) => users.get_user_by_name(n),
                }.context("UI user specified in config not found in passwd")?;
                Some((user.uid(), user.primary_group_id(), PathBuf::from(user.home_dir())))
            },
            None => None,
        };
        UiSpawnConfig {
            binary: binary,
            run_as: run_as,
            env: ui.env,
        }
    };
    let root_factor =
        build_factor_tree(
            &HashSet::new(),
            &config.unlock_config.auth_factors.iter().map(|f| (f.id.clone(), f)).collect(),
            &mut HashMap::new(),
            &config.unlock_config.root_factor,
        )?;

    // Start fg task - drives the separate UI helper process
    let (fg_tx, mut fg_rx) = tokio::sync::mpsc::channel(100);
    tm.critical_task("Foreground interactions", {
        let tm = tm.clone();
        let fg_state = Arc::new(FgState {
            log: log.fork(ea!(sys = "human")),
            last_prompts: Mutex::new(HashMap::new()),
            ui_config: ui_config,
        });
        async move {
            loop {
                let req = select!{
                    r = fg_rx.recv() => r,
                    _ = tm.until_terminate() => break,
                };
                let Some(req) = req else {
                    break;
                };
                match req {
                    B2F::Unlock(req, resp) => {
                        resp.send(fg::do_unlock(fg_state.clone(), Arc::new(req)).await).ignore();
                    },
                    B2F::Initialize(req, resp) => {
                        resp.send(fg::do_initialize(fg_state.clone(), Arc::new(req)).await).ignore();
                    },
                    B2F::Prompt(req, resp) => {
                        resp.send(fg::do_prompt(fg_state.clone(), Arc::new(req)).await).ignore();
                    },
                }
            }
            return Ok(());
        }
    });

    // Prep state for everything else
    struct State {
        fg_tx: tokio::sync::mpsc::Sender<B2F>,
        lock_timeout: u64,
        privdb_path: PathBuf,
        pubdb_path: PathBuf,
        root_factor: Arc<FactorTree>,
        /// The open (unlocked) private database. `None` means locked. The key is not
        /// retained anywhere once the database is open; locking drops the connection.
        db: tokio::sync::Mutex<Option<rusqlite::Connection>>,
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
        db: tokio::sync::Mutex::new(None),
        lock_timeout: config.lock_timeout,
    });

    // Initialize db, process config changes
    let mut pubdbc =
        rusqlite::Connection::open(
            &pubdb_path,
        ).context_with("Error opening pub database", ea!(path = pubdb_path.to_string_lossy()))?;
    pubdb::migrate(
        &mut pubdbc,
    ).context_with("Error setting up pub database", ea!(path = pubdb_path.to_string_lossy()))?;
    shed!{
        'priv_init_done _;
        let mut prev_state = HashMap::new();
        for t in pubdb::factor_list(&mut pubdbc)? {
            prev_state.insert(t.id, t.state);
        }
        if let Some(previous_config) =
            pubdb::config_get(&mut pubdbc).context("Error reading previous config for config migrations")? {
            let (prev_scheme, previous_unlock_config) = match previous_config {
                config::UnlockConfig::V1(config) => (TokenScheme::Legacy, config),
                config::UnlockConfig::V2(config) => (TokenScheme::V2, config),
            };

            // Previous config existed
            let prev_root_factor =
                build_factor_tree(
                    &HashSet::new(),
                    &previous_unlock_config.auth_factors.iter().map(|f| (f.id.clone(), f)).collect(),
                    &mut HashMap::new(),
                    &previous_unlock_config.root_factor,
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
                    if descending && !seen.insert(new.id.clone()) {
                        continue;
                    }
                    let old_variant = old.map(|x| &x.variant);
                    match &new.variant {
                        FactorTreeVariant::And(children) => {
                            if descending {
                                stack.push((new, old, false));
                                let mut old_lookup = HashMap::new();
                                if let Some(FactorTreeVariant::And(old_children)) = old_variant {
                                    for old_child in old_children {
                                        old_lookup.insert(old_child.id.clone(), old_child);
                                    }
                                }
                                for child in children {
                                    stack.push((child, old_lookup.get(&child.id).map(|x| *x), true));
                                }
                            } else {
                                if !matches!(old_variant, Some(FactorTreeVariant::And(_))) {
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
                                if !matches!(old_variant, Some(FactorTreeVariant::Or(_))) {
                                    factor_token_changed.insert(new.id.clone());
                                }
                            }
                        },
                        FactorTreeVariant::Password => {
                            if !matches!(old_variant, Some(FactorTreeVariant::Password)) {
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
                            if !matches!(old_variant, Some(FactorTreeVariant::RecoveryPhrase)) {
                                factor_token_changed.insert(new.id.clone());
                            }
                        },
                    }
                }
                factor_active = seen;
            }
            if prev_scheme == TokenScheme::Legacy {
                log.log(
                    loga::INFO,
                    "Stored unlock data uses the legacy token scheme; the database will be re-keyed after unlocking",
                );
                legacy_scheme_token_changes(&root_factor, &mut factor_token_changed);
            }
            propagate_changes(&root_factor, &mut factor_token_changed, &mut factor_state_changed);

            // Skip if nothing changed
            let root_token_changed =
                prev_scheme == TokenScheme::Legacy || factor_token_changed.contains(&root_factor.id);
            if factor_state_changed.is_empty() && !root_token_changed {
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
                    require_exists: false,
                    root_factor: prev_root_factor.clone(),
                    scheme: prev_scheme,
                    state: prev_state.clone(),
                }, resp_tx)).await.ignore();
                unlock_result =
                    resp_rx.await?.context("Error doing fg unlock")?.context("Config update unlock aborted by user")?;
            }

            // Continue with init
            let (resp_tx, resp_rx) = oneshot::channel();
            state.fg_tx.send(B2F::Initialize(B2FInitialize {
                root_factor: root_factor.clone(),
                tokens_changed: factor_token_changed,
                prev_tokens: unlock_result.tokens,
                state_changed: factor_state_changed,
                prev_state: prev_state,
                prev_root_factor: Some(prev_root_factor),
                prev_scheme: prev_scheme,
            }, resp_tx)).await.ignore();
            let init_result =
                resp_rx
                    .await?
                    .context("Error doing fg initialize")?
                    .context("Credential initialization aborted by user")?;

            // Store the new config and tokens
            let privdbc = unlock_result.privdbc;
            let (_, res) = tx(pubdbc, move |txn| {
                for k in &remove_state {
                    if pubdb::factor_delete(txn, k)
                        .context_with("Error removing obsolete factor data", ea!(factor = k))?
                        .is_none() {
                        return Err(loga::err_with("Obsolete factor data vanished during update", ea!(factor = k)));
                    }
                }
                for (k, v) in &init_result.store_state {
                    pubdb::factor_add(txn, &k, &v).context_with("Error storing new factor data", ea!(factor = k))?;
                }
                pubdb::config_set(txn, &config::UnlockConfig::V2(config.unlock_config))?;
                if root_token_changed {
                    let Some(root_token) = init_result.root_token else {
                        return Err(loga::err("Root token changed but initialization produced no new root token"));
                    };
                    let root_token = root_token.as_bytes();
                    let res = unsafe {
                        libsqlite3_sys::sqlite3_rekey(
                            privdbc.handle(),
                            root_token.as_ptr() as *const c_void,
                            root_token.len() as i32,
                        )
                    };
                    if res != 0 {
                        return Err(loga::err_with("Sqlcipher rekey operation exited with code", ea!(code = res)));
                    }
                }
                return Ok(privdbc);
            }).await;
            let privdbc = res.context("Error committing new unlock credentials")?;

            // Already unlocked, no need to prompt again
            *state.db.lock().await = Some(privdbc);
        }
        else {
            let all_factors = config.unlock_config.auth_factors.iter().map(|x| x.id.clone()).collect::<HashSet<_>>();
            let (resp_tx, resp_rx) = oneshot::channel();
            state.fg_tx.send(B2F::Initialize(B2FInitialize {
                root_factor: root_factor.clone(),
                tokens_changed: all_factors.clone(),
                prev_tokens: HashMap::new(),
                state_changed: all_factors.clone(),
                prev_state: HashMap::new(),
                prev_root_factor: None,
                prev_scheme: TokenScheme::V2,
            }, resp_tx)).await.ignore();
            let init_result =
                resp_rx
                    .await?
                    .context("Error doing fg initialize")?
                    .context("Credential initialization aborted by user")?;
            let Some(root_token) = init_result.root_token.clone() else {
                return Err(loga::err("Initialization produced no root token"));
            };

            // Store the new config and tokens
            let (_, res) = tx(pubdbc, move |txn| {
                for (k, v) in &init_result.store_state {
                    pubdb::factor_add(txn, &k, &v).context_with("Error storing new factor data", ea!(factor = k))?;
                }
                pubdb::config_set(txn, &config::UnlockConfig::V2(config.unlock_config))?;
                return Ok(());
            }).await;
            res.context("Error committing new unlock credentials")?;

            // Create the private database now so that later unlocks can insist it exists
            let privdbc = spawn_blocking({
                let privdb_path = state.privdb_path.clone();
                move || open_privdb(&privdb_path, &root_token)
            }).await.map_err(|e| loga::Error::from(e))?.context("Error creating private database")?;
            *state.db.lock().await = Some(privdbc);
        }
    };

    // Start command server
    let activity = Arc::new(Notify::new());
    let ipc_path = ipc_path();
    let mut ipc_server = ipc::msg::Server::new(&ipc_path).await.map_err(loga::err)?;
    fs::set_permissions(&ipc_path, Permissions::from_mode(0o777))
        .await
        .map_err(loga::err)
        .context("Error setting mode on socket")?;
    tm.critical_task("Command processing", {
        /// Run `f` in a transaction on the private database, unlocking first (via the
        /// UI) if it's locked. Requests are serialized on the database.
        async fn with_db<
            T: 'static + Send,
        >(
            state: &State,
            f: impl 'static + Send + FnOnce(&mut rusqlite::Transaction) -> Result<T, loga::Error>,
        ) -> Result<T, loga::Error> {
            let mut guard = state.db.lock().await;
            if guard.is_none() {
                // Unlock
                let mut pubdbc =
                    rusqlite::Connection::open(&state.pubdb_path).context("Error opening public database")?;
                let mut factor_state = HashMap::new();
                for t in pubdb::factor_list(&mut pubdbc)? {
                    factor_state.insert(t.id, t.state);
                }
                let (fg_result_tx, fg_result_rx) = oneshot::channel();
                state.fg_tx.send(B2F::Unlock(B2FUnlock {
                    privdb_path: state.privdb_path.clone(),
                    require_exists: true,
                    root_factor: state.root_factor.clone(),
                    scheme: TokenScheme::V2,
                    state: factor_state,
                }, fg_result_tx)).await.ignore();
                let res =
                    fg_result_rx.await?.context("Error during fg unlock")?.context("User closed unlock window")?;
                *guard = Some(res.privdbc);
            }
            let conn = guard.take().unwrap();
            let (conn, res) = tx(conn, f).await;
            *guard = conn;
            return res;
        }

        let tm = tm.clone();
        let log = log.clone();
        let tags = Arc::new(Mutex::new(HashMap::<Inode, HashSet<String>>::new()));
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
                let tags = tags.clone();
                spawn(async move {
                    match async {
                        let peer = conn.0.peer_cred()?;
                        let pid = peer.pid().context("OS didn't provide PID for peer")?;
                        let principal = scan_principal(&log, &tags, pid).await?;

                        // Helpers for command processing
                        fn set(txn: &mut rusqlite::Transaction, pairs: Vec<(SpecificPath, serde_json::Value)>) -> Result<(), loga::Error> {
                            let now = Utc::now();
                            let null = serde_json::to_string(&serde_json::Value::Null).unwrap();
                            for (mut path, value) in pairs {
                                // Clear out everything above and below that would be shaded by this
                                for i in 0 .. path.0.len() {
                                    // If setting at `/a/b/c = { .. }` and a value exists at e.g. `/a = 4`
                                    let parent_path = SpecificPath(path.0[..i].iter().cloned().collect()).to_string();
                                    if let Some(existing) = privdb::values_get_exact(txn, &parent_path, i64::MAX)? {
                                        if parse_row_data(&existing.data)? != serde_json::Value::Null {
                                            privdb::values_insert(txn, now, &parent_path, &null)?;
                                        }
                                    }
                                }
                                for row in privdb::values_get(txn, &path.to_string(), i64::MAX)? {
                                    // If setting at `/a/b/c` and a value exists at e.g. `/a/b/c/d`
                                    if parse_row_data(&row.data)? != serde_json::Value::Null {
                                        privdb::values_insert(txn, now, &row.path, &null)?;
                                    }
                                }

                                // Add the new data
                                let mut stack = vec![(None as Option<String>, value, true)];
                                while let Some((seg, at, descending)) = stack.pop() {
                                    if descending {
                                        if let Some(seg) = &seg {
                                            path.0.push(seg.clone());
                                        }
                                        stack.push((seg, at.clone(), false));
                                        match &at {
                                            serde_json::Value::Object(o) => {
                                                for (k, v) in o {
                                                    stack.push((Some(k.to_string()), v.clone(), true));
                                                }
                                            },
                                            _ => {
                                                privdb::values_insert(
                                                    txn,
                                                    now,
                                                    &path.to_string(),
                                                    &serde_json::to_string(&at).unwrap(),
                                                )?;
                                            },
                                        }
                                    } else {
                                        if seg.is_some() {
                                            path.0.pop();
                                        }
                                    }
                                }
                            }
                            return Ok(());
                        }

                        fn get(
                            txn: &mut rusqlite::Transaction,
                            path: &SpecificPath,
                            at: Option<i64>,
                        ) -> Result<serde_json::Value, loga::Error> {
                            let mut root = serde_json::Value::Null;
                            for row in privdb::values_get(txn, &path.to_string(), at.unwrap_or(i64::MAX))? {
                                let data = parse_row_data(&row.data)?;
                                if data == serde_json::Value::Null {
                                    continue;
                                }
                                bury(
                                    &mut root,
                                    &SpecificPath(parse_row_path(&row.path)?.0.split_off(path.0.len())),
                                    data,
                                );
                            }
                            return Ok(root);
                        }

                        /// Get the string value at a path, for keys/urls/etc.
                        fn get_string(
                            txn: &mut rusqlite::Transaction,
                            path: &SpecificPath,
                        ) -> Result<String, loga::Error> {
                            let serde_json::Value::String(s) = get(txn, path, None)? else {
                                return Err(loga::err("No value at path or value is not a string"));
                            };
                            return Ok(s);
                        }

                        // Process request
                        while let Some(req) = conn.recv_req().await.map_err(loga::err)? {
                            enum AuthErr {
                                Err(loga::Error),
                                Unauthorized,
                            }

                            impl From<loga::Error> for AuthErr {
                                fn from(value: loga::Error) -> Self {
                                    return Self::Err(value);
                                }
                            }

                            fn resp_unauthorized() -> Result<ipc::msg::ServerResp, AuthErr> {
                                return Err(AuthErr::Unauthorized);
                            }

                            let resp;
                            match async {
                                let resp;
                                match req {
                                    ipc::msg::ServerReq::Tag(rr, req) => {
                                        let (pidfd_inode, pidfd) =
                                            pidfd(pid).await.context("Error resolving pidfd of peer")?;
                                        log.log_with(
                                            loga::DEBUG,
                                            "Tagging process",
                                            ea!(pid = pid, inode = pidfd_inode.0, tags = req.0.dbg_str()),
                                        );
                                        tags.lock().unwrap().insert(pidfd_inode, req.0.into_iter().collect());
                                        spawn({
                                            let log = log.clone();
                                            let tags = tags.clone();
                                            async move {
                                                let _: Option<AsyncFdReadyGuard<OwnedFd>> =
                                                    match pidfd.readable().await {
                                                        Ok(x) => Some(x),
                                                        Err(e) => {
                                                            log.log_err(
                                                                loga::WARN,
                                                                e.context(
                                                                    format!(
                                                                        "Error waiting for pidfd for pid {:?} to report readable",
                                                                        pid
                                                                    ),
                                                                ),
                                                            );
                                                            None
                                                        },
                                                    };
                                                log.log_with(
                                                    loga::DEBUG,
                                                    "Tagged process exited, untagging",
                                                    ea!(pid = pid, inode = pidfd_inode.0),
                                                );
                                                tags.lock().unwrap().remove(&pidfd_inode);
                                            }
                                        });
                                        resp = rr(());
                                    },
                                    ipc::msg::ServerReq::Lock(rr, req) => {
                                        if !permission::permit(
                                            &log,
                                            state.fg_tx.clone(),
                                            &rules.tree,
                                            &principal,
                                            &[SpecificPath(vec!["".to_string()])],
                                        )
                                            .await?
                                            .lock {
                                            return resp_unauthorized();
                                        }
                                        match req.0 {
                                            ipc::LockAction::Lock => {
                                                *state.db.lock().await = None;
                                            },
                                            ipc::LockAction::Unlock => {
                                                with_db(&state, |_| Ok(())).await?;
                                                activity.notify_one();
                                            },
                                        }
                                        resp = rr(());
                                    },
                                    ipc::msg::ServerReq::MetaKeys(rr, req) => {
                                        if !permission::permit(
                                            &log,
                                            state.fg_tx.clone(),
                                            &rules.tree,
                                            &principal,
                                            &req.paths,
                                        )
                                            .await?
                                            .meta {
                                            return resp_unauthorized();
                                        }
                                        let tree = with_db(&state, move |txn| {
                                            let mut root0 = serde_json::Value::Null;
                                            for path in &req.paths {
                                                let mut root = serde_json::Value::Null;
                                                for row in privdb::values_get(
                                                    txn,
                                                    &path.to_string(),
                                                    req.at.unwrap_or(i64::MAX),
                                                )? {
                                                    let data = parse_row_data(&row.data)?;
                                                    if data == serde_json::Value::Null {
                                                        continue;
                                                    }
                                                    bury(
                                                        &mut root,
                                                        &SpecificPath(
                                                            parse_row_path(&row.path)?.0.split_off(path.0.len()),
                                                        ),
                                                        serde_json::Value::Null,
                                                    );
                                                }
                                                bury(&mut root0, &path, root);
                                            }
                                            return Ok(root0);
                                        }).await?;
                                        activity.notify_one();
                                        resp = rr(serde_json::to_value(&tree).unwrap());
                                    },
                                    ipc::msg::ServerReq::MetaRevisions(rr, req) => {
                                        if !permission::permit(
                                            &log,
                                            state.fg_tx.clone(),
                                            &rules.tree,
                                            &principal,
                                            &req.paths,
                                        )
                                            .await?
                                            .meta {
                                            return resp_unauthorized();
                                        }
                                        let db_resp = with_db(&state, move |txn| {
                                            let mut root = serde_json::Value::Null;
                                            for path in req.paths {
                                                for row in privdb::values_get(
                                                    txn,
                                                    &path.to_string(),
                                                    req.at.unwrap_or(i64::MAX),
                                                )? {
                                                    let data = parse_row_data(&row.data)?;
                                                    bury(
                                                        &mut root,
                                                        &SpecificPath(
                                                            parse_row_path(&row.path)?
                                                                .0
                                                                .into_iter()
                                                                .flat_map(|x| ["children".to_string(), x])
                                                                .collect(),
                                                        ),
                                                        json!({
                                                            "exists": data != serde_json:: Value:: Null,
                                                            "rev_id": row.rev_id,
                                                            "rev_stamp": row.rev_stamp.to_rfc3339(),
                                                        }),
                                                    );
                                                }
                                            }
                                            return Ok(root);
                                        }).await?;
                                        activity.notify_one();
                                        resp = rr(db_resp);
                                    },
                                    ipc::msg::ServerReq::MetaPgpPubkey(rr, req) => {
                                        if !permission::permit(
                                            &log,
                                            state.fg_tx.clone(),
                                            &rules.tree,
                                            &principal,
                                            &vec![req.path.clone()],
                                        )
                                            .await?
                                            .meta {
                                            return resp_unauthorized();
                                        }
                                        let key = with_db(&state, move |txn| get_string(txn, &req.path)).await?;
                                        resp =
                                            rr(
                                                String::from_utf8(
                                                    pgp_from_armor(&key)?
                                                        .armored()
                                                        .to_vec()
                                                        .map_err(loga::err)
                                                        .context("Error serializing ascii-armored pgp cert")?,
                                                ).unwrap(),
                                            );
                                        activity.notify_one();
                                    },
                                    ipc::msg::ServerReq::MetaSshPubkey(rr, req) => {
                                        if !permission::permit(
                                            &log,
                                            state.fg_tx.clone(),
                                            &rules.tree,
                                            &principal,
                                            &vec![req.path.clone()],
                                        )
                                            .await?
                                            .meta {
                                            return resp_unauthorized();
                                        }
                                        let key = with_db(&state, move |txn| get_string(txn, &req.path)).await?;
                                        resp =
                                            rr(
                                                ssh_key::PrivateKey::from_openssh(&key)
                                                    .context("Error reading data at path as openssh private key PEM")?
                                                    .public_key()
                                                    .to_openssh()
                                                    .context("Error encoding ssh public key as openssh PEM")?,
                                            );
                                        activity.notify_one();
                                    },
                                    ipc::msg::ServerReq::Read(rr, req) => {
                                        if !permission::permit(
                                            &log,
                                            state.fg_tx.clone(),
                                            &rules.tree,
                                            &principal,
                                            &req.paths,
                                        )
                                            .await?
                                            .read {
                                            return resp_unauthorized();
                                        }
                                        let tree = with_db(&state, move |txn| {
                                            let mut root = serde_json::Value::Null;
                                            for path in &req.paths {
                                                bury(&mut root, &path, get(txn, path, req.at)?);
                                            }
                                            return Ok(root);
                                        }).await?;
                                        activity.notify_one();
                                        resp = rr(serde_json::to_value(&tree).unwrap());
                                    },
                                    ipc::msg::ServerReq::Write(rr, req) => {
                                        if !permission::permit(
                                            &log,
                                            state.fg_tx.clone(),
                                            &rules.tree,
                                            &principal,
                                            &req.0.iter().map(|(path, _)| path.clone()).collect::<Vec<_>>(),
                                        )
                                            .await?
                                            .write {
                                            return resp_unauthorized();
                                        }
                                        with_db(&state, move |txn| {
                                            set(txn, req.0)?;
                                            return Ok(());
                                        }).await?;
                                        activity.notify_one();
                                        resp = rr(());
                                    },
                                    ipc::msg::ServerReq::WriteMove(rr, req) => {
                                        if !permission::permit(
                                            &log,
                                            state.fg_tx.clone(),
                                            &rules.tree,
                                            &principal,
                                            &[req.from.clone(), req.to.clone()],
                                        )
                                            .await?
                                            .write {
                                            return resp_unauthorized();
                                        }
                                        with_db(&state, move |txn| {
                                            if get(txn, &req.to, None)? != serde_json::Value::Null && !req.overwrite {
                                                return Err(
                                                    loga::err(
                                                        "Attempt to move over existing value with overwrite off",
                                                    ),
                                                );
                                            }
                                            let data = get(txn, &req.from, None)?;
                                            set(txn, vec![(req.from, serde_json::Value::Null), (req.to, data)])?;
                                            return Ok(());
                                        }).await?;
                                        activity.notify_one();
                                        resp = rr(());
                                    },
                                    ipc::msg::ServerReq::WriteGenerate(rr, req) => {
                                        if !permission::permit(
                                            &log,
                                            state.fg_tx.clone(),
                                            &rules.tree,
                                            &principal,
                                            &[req.path.clone()],
                                        )
                                            .await?
                                            .write {
                                            return resp_unauthorized();
                                        }
                                        with_db(&state, move |txn| {
                                            if get(txn, &req.path, None)? != serde_json::Value::Null &&
                                                !req.overwrite {
                                                return Err(
                                                    loga::err("Destructive command but flag to allow not specified"),
                                                );
                                            }
                                            let data;
                                            match req.variant {
                                                ipc::C2SGenerateVariant::Bytes(args) => {
                                                    data =
                                                        serde_json::Value::String(
                                                            to_b32(&generate::gen_bytes(args.length)),
                                                        );
                                                },
                                                ipc::C2SGenerateVariant::SafeAlphanumeric(args) => {
                                                    data =
                                                        serde_json::Value::String(
                                                            generate::gen_safe_alphanum(args.length),
                                                        );
                                                },
                                                ipc::C2SGenerateVariant::Alphanumeric(args) => {
                                                    data =
                                                        serde_json::Value::String(
                                                            generate::gen_alphanum(args.length),
                                                        );
                                                },
                                                ipc::C2SGenerateVariant::AlphanumericSymbols(args) => {
                                                    data =
                                                        serde_json::Value::String(
                                                            generate::gen_alphanum_symbols(args.length),
                                                        );
                                                },
                                                ipc::C2SGenerateVariant::Pgp => {
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
                                                        &cert.as_tsk().armored(),
                                                        &mut w,
                                                    )
                                                        .map_err(|e| loga::err(e.to_string()))
                                                        .context("Error serializing private key")?;
                                                    data =
                                                        serde_json::Value::String(
                                                            String::from_utf8(w.finalize()?).unwrap(),
                                                        );
                                                },
                                                ipc::C2SGenerateVariant::Ssh => {
                                                    let key =
                                                        ssh_key::PrivateKey::random(
                                                            &mut ssh_key::rand_core::OsRng,
                                                            ssh_key::Algorithm::default(),
                                                        ).context("Error generating ssh key")?;
                                                    data =
                                                        serde_json::Value::String(
                                                            key
                                                                .to_openssh(Default::default())
                                                                .context(
                                                                    "Error encoding ssh key in openssh PEM format",
                                                                )?
                                                                .to_string(),
                                                        );
                                                },
                                            };
                                            set(txn, vec![(req.path, data)])?;
                                            return Ok(());
                                        }).await?;
                                        activity.notify_one();
                                        resp = rr(());
                                    },
                                    ipc::msg::ServerReq::WriteRevert(rr, req) => {
                                        if !permission::permit(
                                            &log,
                                            state.fg_tx.clone(),
                                            &rules.tree,
                                            &principal,
                                            &req.paths,
                                        )
                                            .await?
                                            .write {
                                            return resp_unauthorized();
                                        }
                                        with_db(&state, move |txn| {
                                            for path in req.paths {
                                                let data = get(txn, &path, Some(req.at))?;
                                                set(txn, vec![(path, data)])?;
                                            }
                                            return Ok(()) as Result<_, loga::Error>;
                                        }).await?;
                                        activity.notify_one();
                                        resp = rr(());
                                    },
                                    ipc::msg::ServerReq::DerivePgpSign(rr, req) => {
                                        if !permission::permit(
                                            &log,
                                            state.fg_tx.clone(),
                                            &rules.tree,
                                            &principal,
                                            &[req.key.clone()],
                                        )
                                            .await?
                                            .derive {
                                            return resp_unauthorized();
                                        }
                                        let key = with_db(&state, move |txn| get_string(txn, &req.key)).await?;
                                        let mut signed = vec![];
                                        let mut signer =
                                            Signer::with_template(
                                                Message::new(&mut signed),
                                                pgp_from_armor(&key)?
                                                    .keys()
                                                    .secret()
                                                    .with_policy(&StandardPolicy::new(), None)
                                                    .supported()
                                                    .for_signing()
                                                    .nth(0)
                                                    .context("Pgp cert at path has no usable signing key")?
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
                                        let mut armorer =
                                            sequoia_openpgp::armor::Writer::new(
                                                Vec::new(),
                                                sequoia_openpgp::armor::Kind::Signature,
                                            ).context("Error instantiating gpg armorer")?;
                                        armorer
                                            .write_all(&signed)
                                            .map_err(loga::err)
                                            .context("Error writing signature to ascii-armorer")?;
                                        resp =
                                            rr(
                                                String::from_utf8(
                                                    armorer
                                                        .finalize()
                                                        .context("Error finalizing gpg armor on signature")?,
                                                ).unwrap(),
                                            );
                                        activity.notify_one();
                                    },
                                    ipc::msg::ServerReq::DerivePgpDecrypt(rr, req) => {
                                        if !permission::permit(
                                            &log,
                                            state.fg_tx.clone(),
                                            &rules.tree,
                                            &principal,
                                            &[req.key.clone()],
                                        )
                                            .await?
                                            .derive {
                                            return resp_unauthorized();
                                        }
                                        let key = with_db(&state, move |txn| get_string(txn, &req.key)).await?;
                                        let mut decrypted = vec![];

                                        struct Helper(Cert, Key<SecretParts, UnspecifiedRole>);

                                        impl sequoia_openpgp::parse::stream::VerificationHelper for Helper {
                                            fn check(
                                                &mut self,
                                                _structure: sequoia_openpgp::parse::stream::MessageStructure,
                                            ) -> sequoia_openpgp::Result<()> {
                                                return Ok(());
                                            }

                                            fn get_certs(
                                                &mut self,
                                                ids: &[sequoia_openpgp::KeyHandle],
                                            ) -> sequoia_openpgp::Result<Vec<Cert>> {
                                                let own_id = self.1.key_handle();
                                                for id in ids {
                                                    if id.aliases(&own_id) {
                                                        return Ok(vec![self.0.clone()]);
                                                    }
                                                }
                                                return Ok(vec![]);
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
                                                let mut keypair = self.1.clone().into_keypair()?;
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
                                        let cert = pgp_from_armor(&key)?;
                                        let secret_key =
                                            cert
                                                .keys()
                                                .secret()
                                                .with_policy(&policy, None)
                                                .supported()
                                                .for_storage_encryption()
                                                .nth(0)
                                                .context("Pgp cert at path has no usable storage encryption key")?
                                                .key()
                                                .clone();
                                        let mut decryptor =
                                            DecryptorBuilder::from_bytes(&req.data)
                                                .map_err(loga::err)
                                                .context("Error creating decryptor from data to decrypt")?
                                                .with_policy(&policy, None, Helper(cert, secret_key))
                                                .map_err(loga::err)
                                                .context("Error matching cert to data to decrypt")?;
                                        std::io::copy(&mut decryptor, &mut Cursor::new(&mut decrypted))
                                            .map_err(loga::err)
                                            .context("Error decrypting data")?;
                                        activity.notify_one();
                                        resp = rr(decrypted);
                                    },
                                    ipc::msg::ServerReq::DeriveOtp(rr, req) => {
                                        if !permission::permit(
                                            &log,
                                            state.fg_tx.clone(),
                                            &rules.tree,
                                            &principal,
                                            &[req.key.clone()],
                                        )
                                            .await?
                                            .derive {
                                            return resp_unauthorized();
                                        }
                                        let otp_url = with_db(&state, move |txn| get_string(txn, &req.key)).await?;
                                        let otp =
                                            totp_rs::TOTP::from_url_unchecked(
                                                &otp_url,
                                            ).context("Failed to parse OTP url at path")?;
                                        let token = otp.generate_current().context("Error generating OTP token")?;
                                        activity.notify_one();
                                        resp = rr(token);
                                    },
                                }
                                return Ok(resp);
                            }.await {
                                Ok(r) => {
                                    resp = r;
                                },
                                Err(e) => {
                                    match e {
                                        AuthErr::Err(e) => {
                                            log.log_err(loga::WARN, e.context("Error processing request"));
                                            resp = ipc::msg::ServerResp::err("Encountered error processing request");
                                        },
                                        AuthErr::Unauthorized => {
                                            resp = ipc::msg::ServerResp::err("Unauthorized");
                                        },
                                    }
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
                        next = Some(Instant::now() + Duration::from_secs(state.lock_timeout));
                    }
                    _ = async {
                        sleep_until(next.take().unwrap()).await
                    },
                    if next.is_some() => {
                        log.log(loga::DEBUG, "Activity timeout, locking");
                        *state.db.lock().await = None;
                    }
                }
            }
        }
    });

    // Start bg tasks (timeouts mainly) Wait forever
    tm.join(&log).await?;
    return Ok(());
}
