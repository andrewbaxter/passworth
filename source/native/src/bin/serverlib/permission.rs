use {
    crate::serverlib::fg::{
        B2FPrompt,
        B2F,
    },
    flowcontrol::shed,
    loga::{
        ea,
        DebugDisplay,
        ErrContext,
        Log,
        ResultContext,
    },
    passworth::{
        datapath::{
            GlobPath,
            GlobSeg,
            SpecificPath,
        },
    },
    passworth_native::{
        config::{
            latest::{
                ConfigPermissionRule,
                ConfigPrompt,
                MatchBinary,
                UserGroupId,
            },
            v1::PermitLevel,
        },
    },
    std::{
        collections::HashMap,
        io::ErrorKind,
        mem::swap,
        os::unix::fs::MetadataExt,
        path::PathBuf,
        str::FromStr,
        sync::Arc,
    },
    tokio::{
        fs::{
            read,
            read_link,
        },
        sync::oneshot,
    },
    users::{
        Groups,
        Users,
        UsersCache,
    },
};

#[derive(Debug)]
pub struct RuleMatchUser {
    pub user_id: Option<u32>,
    pub group_id: Option<u32>,
    pub walk_ancestors: usize,
}

#[derive(Debug)]
pub struct Rule {
    pub id: usize,
    pub match_systemd: Option<String>,
    pub match_user: Option<RuleMatchUser>,
    pub match_binary: Option<MatchBinary>,
    pub permit: PermitLevel,
    pub prompt: Option<ConfigPrompt>,
}

#[derive(Default, Debug)]
pub struct RuleTree {
    pub rules: Vec<Arc<Rule>>,
    pub wildcard: Option<Box<RuleTree>>,
    pub children: HashMap<String, RuleTree>,
}

#[derive(Clone)]
pub struct RuleTreeRoot {
    pub tree: Arc<RuleTree>,
    pub any_match_systemd: bool,
    pub any_match_binary: bool,
}

pub fn build_rule_tree(
    users: &UsersCache,
    config_rules: &[ConfigPermissionRule],
) -> Result<RuleTreeRoot, loga::Error> {
    let mut rules = RuleTree::default();
    let mut any_match_systemd = false;
    let mut any_match_binary = false;
    for (id, rule) in config_rules.iter().enumerate() {
        if rule.match_systemd.is_some() {
            any_match_systemd = true;
        }
        if rule.match_binary.is_some() {
            any_match_binary = true;
        }
        let out_rule = Arc::new(Rule {
            id: id,
            match_binary: rule.match_binary.clone(),
            match_systemd: rule.match_systemd.clone(),
            match_user: match &rule.match_user {
                Some(u) => Some(RuleMatchUser {
                    user_id: match &u.user {
                        Some(u) => Some(match u {
                            UserGroupId::Name(n) => users
                                .get_user_by_name(&n)
                                .context(format!("Rule specifies user {} but no such user found in pwd", n))?
                                .uid(),
                            UserGroupId::Id(i) => *i,
                        }),
                        None => None,
                    },
                    group_id: match &u.group {
                        Some(u) => Some(match u {
                            UserGroupId::Name(n) => users
                                .get_group_by_name(&n)
                                .context(format!("Rule specifies group {} but no such group found in pwd", n))?
                                .gid(),
                            UserGroupId::Id(i) => *i,
                        }),
                        None => None,
                    },
                    walk_ancestors: u.walk_ancestors,
                }),
                None => None,
            },
            permit: rule.permit,
            prompt: rule.prompt.clone(),
        });
        for path in &rule.paths {
            let segs = GlobPath::from_str(path).map_err(loga::err)?;
            let mut at = &mut rules;
            for seg in segs.0 {
                match seg {
                    GlobSeg::Lit(seg) => {
                        at = at.children.entry(seg).or_default();
                    },
                    GlobSeg::Glob => {
                        at = at.wildcard.get_or_insert_with(|| Box::new(RuleTree::default()));
                    },
                }
            }
            at.rules.push(out_rule.clone());
        }
    }
    return Ok(RuleTreeRoot {
        tree: Arc::new(rules),
        any_match_systemd: any_match_systemd,
        any_match_binary: any_match_binary,
    });
}

pub struct PrincipalMetaProc {
    pid: i32,
    uid: Option<u32>,
    gid: Option<u32>,
    systemd: Option<String>,
    binary: Option<PathBuf>,
}

pub struct PrincipalMeta {
    /// Starts at process, then first parent, then 2nd, etc.
    chain: Vec<PrincipalMetaProc>,
}

pub async fn scan_principal(
    log: &Log,
    scan_systemd: bool,
    scan_binary: bool,
    pid: i32,
) -> Result<PrincipalMeta, loga::Error> {
    // Get list of current systemd services for auth rule matching
    let mut service_pids = HashMap::new();
    if scan_systemd {
        shed!{
            let mut command = tokio::process::Command::new("systemctl");
            command.args(["show", "*", "--type", "service", "--property", "Id,ExecMainPID"]);
            let log = log.fork(ea!(command = command.dbg_str()));
            let res = command.output().await?;
            if !res.status.success() {
                log.log_with(
                    loga::WARN,
                    "Error listing current systemd service PIDs",
                    ea!(output = res.pretty_dbg_str()),
                );
                break;
            }
            let mut pid = None;
            let mut name = None;
            for line in res.stdout.split(|x| *x == b'\n') {
                if line.is_empty() {
                    if let Some((pid, name)) = pid.zip(name) {
                        service_pids.insert(pid, name);
                    }
                    pid = None;
                    name = None;
                    continue;
                }
                let log = log.fork(ea!(line = String::from_utf8_lossy(&line)));
                let mut splits = line.splitn(2, |x| *x == b'=');
                let Some((key, value)) = splits.next().zip(splits.next()) else {
                    log.log_err(loga::WARN, loga::err("Non KV line in systemd service PID list output"));
                    continue;
                };
                match key {
                    b"ExecMainPID" => {
                        let pid0 = match i32::from_str_radix(&String::from_utf8_lossy(&value), 10) {
                            Ok(x) => x,
                            Err(e) => {
                                log.log_err(
                                    loga::WARN,
                                    e.context("Found unparsable PID in systemd service PID list"),
                                );
                                continue;
                            },
                        };
                        pid = Some(pid0)
                    },
                    b"Id" => name = Some(String::from_utf8_lossy(&value).to_string()),
                    _ => {
                        log.log(loga::WARN, "Got invalid line in systemd service PID list");
                        continue;
                    },
                }
            }
            if let Some((pid, name)) = pid.zip(name) {
                service_pids.insert(pid, name);
            }
        }
    }
    log.log(loga::DEBUG, format!("Scan principal: systemd PIDs: {:?}", service_pids));

    // Get peer pid chain
    let mut trunk = vec![];
    let mut at = pid;
    loop {
        let proc_path = PathBuf::from(format!("/proc/{}", at));

        // Parse important values from stat lines
        let mut parent_pid = None;
        let mut uid = None;
        let mut gid = None;
        for line in read(proc_path.join("status")).await?.split(|x| *x == b'\n') {
            let mut splits = line.splitn(2, |x| *x == b':');
            let Some((key, value)) = splits.next().zip(splits.next()) else {
                continue;
            };
            match key {
                b"PPid" => {
                    parent_pid = match i32::from_str_radix(String::from_utf8_lossy(&value).trim(), 10) {
                        Ok(pid) => Some(pid),
                        Err(e) => {
                            log.log_err(loga::WARN, e.context("Got invalid ppid from proc tree status output"));
                            continue;
                        },
                    };
                },
                b"Uid" => {
                    let splits = value.split(|x| *x == b'\t').filter(|x| !x.is_empty()).collect::<Vec<_>>();

                    // Priorities: Effective, real
                    uid = match splits.get(1).or(splits.get(0)) {
                        Some(value) => {
                            match u32::from_str_radix(&String::from_utf8_lossy(*value), 10) {
                                Ok(value) => Some(value),
                                Err(e) => {
                                    log.log_err(
                                        loga::WARN,
                                        e.context("Got invalid uid from proc tree status output"),
                                    );
                                    continue;
                                },
                            }
                        },
                        None => None,
                    };
                },
                b"Gid" => {
                    let splits = value.split(|x| *x == b'\t').filter(|x| !x.is_empty()).collect::<Vec<_>>();

                    // Priorities: Effective, real
                    gid = match splits.get(1).or(splits.get(0)) {
                        Some(value) => {
                            match u32::from_str_radix(&String::from_utf8_lossy(*value), 10) {
                                Ok(value) => Some(value),
                                Err(e) => {
                                    log.log_err(
                                        loga::WARN,
                                        e.context("Got invalid uid from proc tree status output"),
                                    );
                                    continue;
                                },
                            }
                        },
                        None => None,
                    };
                },
                _ => { },
            }
        }

        // Build meta chain entry
        let binary = if scan_binary {
            match async {
                let exe_path = proc_path.join("exe");
                let exe_rel =
                    read_link(&exe_path)
                        .await
                        .context_with("Unable to read proc exe link", ea!(path = exe_path.dbg_str()))?;
                let root_exe = match tokio::fs::metadata(&exe_rel).await {
                    Ok(x) => x,
                    Err(e) => {
                        if e.kind() == ErrorKind::NotFound {
                            return Ok(None);
                        }
                        return Err(e.context_with("Error reading exe meta on root", ea!(path = exe_rel.dbg_str())));
                    },
                };
                let proc_path = proc_path.join("root").join(&exe_rel);
                let proc_exe = match tokio::fs::metadata(&proc_path).await {
                    Ok(x) => x,
                    Err(e) => {
                        if e.kind() == ErrorKind::NotFound {
                            return Ok(None);
                        }
                        return Err(
                            e.context_with(
                                "Error reading exe meta within proc mount",
                                ea!(path = proc_path.dbg_str()),
                            ),
                        );
                    },
                };

                // Permissions are based on binaries in root namespace; confirm binary is the same
                // as the one on root or else treat as unknown
                if root_exe.dev() == proc_exe.dev() {
                    return Ok(Some(exe_rel));
                } else {
                    return Ok(None);
                }
            }.await {
                Ok(x) => x,
                Err(e) => {
                    log.log_err(loga::WARN, e.context("Unable to read proc exe link"));
                    None
                },
            }
        } else {
            None
        };
        let systemd = service_pids.get(&at).cloned();
        log.log_with(
            loga::DEBUG,
            format!("Scan principal: scan PID {}", at),
            ea!(uid = uid.dbg_str(), gid = gid.dbg_str(), systemd = systemd.dbg_str(), binary = binary.dbg_str()),
        );
        trunk.push(PrincipalMetaProc {
            pid: at,
            uid: uid,
            gid: gid,
            systemd: systemd,
            binary: binary,
        });

        // Ascend
        let parent_pid = parent_pid.unwrap();
        if parent_pid == 0 {
            break;
        }
        at = parent_pid;
    }
    return Ok(PrincipalMeta { chain: trunk });
}

pub struct Perms {
    pub lock: bool,
    pub meta: bool,
    pub derive: bool,
    pub read: bool,
    pub write: bool,
}

pub async fn permit(
    log: &Log,
    fg_tx: tokio::sync::mpsc::Sender<B2F>,
    rules: &RuleTree,
    principal: &PrincipalMeta,
    paths: &[SpecificPath],
) -> Result<Perms, loga::Error> {
    let mut total_lock = true;
    let mut total_meta = true;
    let mut total_derive = true;
    let mut total_read = true;
    let mut total_write = true;

    struct TotalPrompt {
        rules: HashMap<usize, (String, u64)>,
    }

    let mut total_prompt = None;
    for path in paths {
        log.log(loga::DEBUG, format!("Permit: Testing permissions for path {:?}", path.0));
        let mut new_tails = vec![];
        let mut tails = vec![rules];
        let mut path_lock = false;
        let mut path_meta = false;
        let mut path_derive = false;
        let mut path_read = false;
        let mut path_write = false;
        let mut segs = path.0.iter();
        loop {
            let seg = segs.next();
            for tail in tails.drain(..) {
                for rule in &tail.rules {
                    let mut matched = true;
                    if let Some(match_binary) = &rule.match_binary {
                        let submatch = shed!{
                            'submatch _;
                            for (depth, proc) in principal.chain.iter().enumerate() {
                                if proc.binary.as_ref() == Some(&match_binary.path) {
                                    log.log(loga::DEBUG, format!("Permit: MATCHED binary at [{}]", proc.pid));
                                    break 'submatch true;
                                } else {
                                    log.log(
                                        loga::DEBUG,
                                        format!(
                                            "Permit: Binary mismatch at [{}], got {} want {}",
                                            proc.pid,
                                            proc.binary.dbg_str(),
                                            match_binary.path.dbg_str()
                                        ),
                                    );
                                }
                                if depth >= match_binary.walk_ancestors {
                                    log.log(
                                        loga::DEBUG,
                                        format!(
                                            "Permit: Didn't match binary at [{}], depth {}, not walking ancestors",
                                            proc.pid,
                                            depth
                                        ),
                                    );
                                    break 'submatch false;
                                }
                            }
                            break 'submatch false;
                        };
                        matched = matched && submatch;
                    }
                    if let Some(match_systemd) = &rule.match_systemd {
                        let submatch = shed!{
                            'submatch _;
                            for proc in &principal.chain {
                                if proc.systemd.as_ref() == Some(match_systemd) {
                                    log.log(loga::DEBUG, format!("Permit: MATCHED systemd at [{}]", proc.pid));
                                    break 'submatch true;
                                }
                                log.log(
                                    loga::DEBUG,
                                    format!(
                                        "Permit: Systemd mismatch at [{}], got {} want {}",
                                        proc.pid.dbg_str(),
                                        proc.systemd.dbg_str(),
                                        match_systemd
                                    ),
                                );
                            }
                            break 'submatch false;
                        };
                        matched = matched && submatch;
                    }
                    if let Some(match_user) = &rule.match_user {
                        let submatch = shed!{
                            'submatch _;
                            for (depth, proc) in principal.chain.iter().enumerate() {
                                shed!{
                                    if let Some(match_user_id) = &match_user.user_id {
                                        if proc.uid.as_ref() != Some(match_user_id) {
                                            log.log(
                                                loga::DEBUG,
                                                format!(
                                                    "Permit: UID mismatch at [{}], got {} want {}",
                                                    proc.pid,
                                                    proc.uid.dbg_str(),
                                                    match_user_id
                                                ),
                                            );
                                            break;
                                        }
                                        log.log(loga::DEBUG, format!("Permit: MATCHED UID at [{}]", proc.pid));
                                    }
                                    if let Some(match_group_id) = &match_user.group_id {
                                        if proc.gid.as_ref() != Some(match_group_id) {
                                            log.log(
                                                loga::DEBUG,
                                                format!(
                                                    "Permit: GID mismatch at [{}], got {} want {}",
                                                    proc.pid,
                                                    proc.gid.dbg_str(),
                                                    match_group_id
                                                ),
                                            );
                                            break;
                                        }
                                        log.log(loga::DEBUG, format!("Permit: MATCHED GID at [{}]", proc.pid));
                                    }
                                    break 'submatch true;
                                }
                                if depth >= match_user.walk_ancestors {
                                    matched = false;
                                    log.log(
                                        loga::DEBUG,
                                        format!(
                                            "Permit: Didn't match user at [{}], depth {}, not walking ancestors",
                                            proc.pid,
                                            depth
                                        ),
                                    );
                                    break;
                                }
                            }
                            break 'submatch false;
                        };
                        matched = matched && submatch;
                    }
                    if !matched {
                        continue;
                    }

                    // Path permissions are union of permissions for each matching rule
                    path_write = path_write || rule.permit as usize >= PermitLevel::Write as usize;
                    path_read = path_read || rule.permit as usize >= PermitLevel::Read as usize;
                    path_derive = path_derive || rule.permit as usize >= PermitLevel::Derive as usize;
                    path_meta = path_meta || rule.permit as usize >= PermitLevel::Meta as usize;
                    path_lock = path_lock || rule.permit as usize >= PermitLevel::Lock as usize;
                    if let Some(rule_prompt) = &rule.prompt {
                        let prompt = total_prompt.get_or_insert_with(|| TotalPrompt { rules: HashMap::new() });
                        prompt
                            .rules
                            .insert(rule.id, (rule_prompt.description.clone(), rule_prompt.remember_seconds));
                    }
                }

                // Descend
                if let Some(seg) = seg {
                    if let Some(wildcard) = &tail.wildcard {
                        new_tails.push(wildcard.as_ref());
                    }
                    if let Some(child) = tail.children.get(seg) {
                        new_tails.push(child);
                    }
                }
            }
            swap(&mut tails, &mut new_tails);
            if seg.is_none() {
                break;
            }
        }

        // Overall permissions are most restrictive of permissions for any path
        total_lock = total_lock && path_lock;
        total_meta = total_meta && path_meta;
        total_derive = total_derive && path_derive;
        total_read = total_read && path_read;
        total_write = total_write && path_write;
    }
    if let Some(prompt) = total_prompt {
        let (resp_tx, resp_rx) = oneshot::channel();
        fg_tx.send(B2F::Prompt(B2FPrompt { prompt_rules: prompt.rules.clone() }, resp_tx)).await?;
        match resp_rx.await.unwrap() {
            Ok(Some(b)) => {
                if !b {
                    return Err(loga::err("User rejected access request"));
                }
            },
            Ok(None) => {
                return Err(loga::err("User rejected access request"));
            },
            Err(e) => {
                return Err(e);
            },
        }
    }
    return Ok(Perms {
        lock: total_lock,
        meta: total_meta,
        derive: total_derive,
        read: total_read,
        write: total_write,
    });
}
