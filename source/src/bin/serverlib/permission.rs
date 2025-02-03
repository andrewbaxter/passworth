use {
    super::datapath::{
        glob_from_db_path,
        GlobSeg,
    },
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
    passworth::config::latest::{
        ConfigPermissionRule,
        ConfigPrompt,
        MatchBinary,
        UserGroupId,
    },
    std::{
        collections::HashMap,
        io::ErrorKind,
        mem::swap,
        os::unix::fs::MetadataExt,
        path::PathBuf,
        sync::Arc,
    },
    tokio::{
        fs::{
            read,
            read_link,
        },
        sync::{
            mpsc,
            oneshot,
        },
    },
    users::{
        Groups,
        Users,
        UsersCache,
    },
};

pub struct RuleMatchUser {
    pub user_id: Option<u32>,
    pub group_id: Option<u32>,
    pub walk_ancestors: bool,
}

pub struct Rule {
    pub id: usize,
    pub match_systemd: Option<String>,
    pub match_user: Option<RuleMatchUser>,
    pub match_binary: Option<MatchBinary>,
    pub permit_lock: bool,
    pub permit_derive: bool,
    pub permit_read: bool,
    pub permit_write: bool,
    pub prompt: Option<ConfigPrompt>,
}

#[derive(Default)]
pub struct RuleTree {
    pub rules: Vec<Arc<Rule>>,
    pub wildcard: Option<Box<RuleTree>>,
    pub children: HashMap<String, RuleTree>,
}

pub fn build_rule_tree(
    users: &UsersCache,
    config_rules: &[ConfigPermissionRule],
) -> Result<Arc<RuleTree>, loga::Error> {
    let mut rules = RuleTree::default();
    for (id, rule) in config_rules.iter().enumerate() {
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
            permit_derive: rule.permit_derive,
            permit_lock: rule.permit_lock,
            permit_read: rule.permit_read,
            permit_write: rule.permit_write,
            prompt: rule.prompt.clone(),
        });
        for path in &rule.paths {
            let segs = glob_from_db_path(path)?;
            let mut at = &mut rules;
            for seg in segs {
                match seg {
                    GlobSeg::Literal(seg) => {
                        at = at.children.entry(seg).or_default();
                    },
                    GlobSeg::Wildcard => {
                        at = at.wildcard.get_or_insert_with(|| Box::new(RuleTree::default()));
                    },
                }
            }
            at.rules.push(out_rule.clone());
        }
    }
    return Ok(Arc::new(rules));
}

pub struct PrincipalMetaProc {
    uid: Option<u32>,
    gid: Option<u32>,
    systemd: Option<String>,
    binary: Option<PathBuf>,
}

pub struct PrincipalMeta {
    chain: Vec<PrincipalMetaProc>,
}

pub async fn scan_principal(log: &Log, pid: i32) -> Result<PrincipalMeta, loga::Error> {
    // Get list of current systemd services for auth rule matching
    let mut service_pids = HashMap::new();
    {
        let mut command = tokio::process::Command::new("systemctl");
        command.args(["*", "--type", "service", "--properties", "ID,ExecMainPID"]);
        let log = log.fork(ea!(command = command.dbg_str()));
        let res = command.output().await?;
        if !res.status.success() {
            return Err(
                loga::err_with("Error listing current systemd service PIDs", ea!(output = res.pretty_dbg_str())),
            );
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
                            log.log_err(loga::WARN, e.context("Found unparsable PID in systemd service PID list"));
                            continue;
                        },
                    };
                    pid = Some(pid0)
                },
                b"ID" => name = Some(String::from_utf8_lossy(&value).to_string()),
                _ => {
                    log.log(loga::WARN, "Got invalid line in systemd service PID list");
                    continue;
                },
            }
        }
    }

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
        let binary = match async {
            let exe_rel = read_link(proc_path.join("exe")).await.context("Unable to read proc exe link")?;
            let root_exe = match tokio::fs::metadata(&exe_rel).await {
                Ok(x) => x,
                Err(e) => {
                    if e.kind() == ErrorKind::NotFound {
                        return Ok(None);
                    }
                    return Err(e.context("Error reading exe meta on root"));
                },
            };
            let proc_exe = match tokio::fs::metadata(proc_path.join("root").join(&exe_rel)).await {
                Ok(x) => x,
                Err(e) => {
                    if e.kind() == ErrorKind::NotFound {
                        return Ok(None);
                    }
                    return Err(e.context("Error reading exe meta within proc mount"));
                },
            };
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
        };
        trunk.push(PrincipalMetaProc {
            uid: uid,
            gid: gid,
            systemd: service_pids.get(&at).cloned(),
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
    pub derive: bool,
    pub read: bool,
    pub write: bool,
}

pub async fn permit(
    fg_tx: mpsc::Sender<B2F>,
    rules: &RuleTree,
    principal: &PrincipalMeta,
    paths: &[Vec<String>],
) -> Result<Perms, loga::Error> {
    let mut total_lock = true;
    let mut total_derive = true;
    let mut total_read = true;
    let mut total_write = true;

    struct TotalPrompt {
        rules: HashMap<usize, (String, u64)>,
    }

    let mut total_prompt = None;
    for path in paths {
        let mut path_lock = false;
        let mut path_derive = false;
        let mut path_read = false;
        let mut path_write = false;
        let mut tails = vec![rules];
        let mut new_tails = vec![];
        for seg in path {
            for tail in tails.drain(..) {
                for rule in &tail.rules {
                    let mut matched = true;
                    if let Some(match_binary) = &rule.match_binary {
                        let submatch = shed!{
                            'done_match _;
                            for proc in &principal.chain {
                                if proc.binary.as_ref() == Some(&match_binary.path) {
                                    break 'done_match true;
                                }
                                if !match_binary.walk_ancestors {
                                    break 'done_match false;
                                }
                            }
                            break 'done_match false;
                        };
                        matched = matched && submatch;
                    }
                    if let Some(match_systemd) = &rule.match_systemd {
                        let submatch = shed!{
                            'done_match _;
                            for proc in &principal.chain {
                                if proc.systemd.as_ref() == Some(match_systemd) {
                                    break 'done_match true;
                                }
                            }
                            break 'done_match false;
                        };
                        matched = matched && submatch;
                    }
                    if let Some(match_user) = &rule.match_user {
                        let submatch = shed!{
                            'done_match _;
                            for proc in &principal.chain {
                                shed!{
                                    if let Some(match_user_id) = &match_user.user_id {
                                        if proc.uid.as_ref() != Some(match_user_id) {
                                            break;
                                        }
                                    }
                                    if let Some(match_group_id) = &match_user.group_id {
                                        if proc.gid.as_ref() != Some(match_group_id) {
                                            break;
                                        }
                                    }
                                    break 'done_match true;
                                }
                                if !match_user.walk_ancestors {
                                    matched = false;
                                    break;
                                }
                            }
                            break 'done_match false;
                        };
                        matched = matched && submatch;
                    }
                    if !matched {
                        continue;
                    }

                    // Path permissions are union of permissions for each matching rule
                    path_lock = path_lock || rule.permit_lock;
                    path_derive = path_derive || rule.permit_derive;
                    path_read = path_read || rule.permit_read;
                    path_write = path_write || rule.permit_write;
                    if let Some(rule_prompt) = &rule.prompt {
                        let prompt = total_prompt.get_or_insert_with(|| TotalPrompt { rules: HashMap::new() });
                        prompt
                            .rules
                            .insert(rule.id, (rule_prompt.description.clone(), rule_prompt.remember_seconds));
                    }
                }

                // Recurse
                if let Some(wildcard) = &tail.wildcard {
                    new_tails.push(wildcard.as_ref());
                }
                if let Some(child) = tail.children.get(seg) {
                    new_tails.push(child);
                }
            }
            swap(&mut tails, &mut new_tails);
        }

        // Overall permissions are most restrictive of permissions for any path
        total_lock = total_lock && path_lock;
        total_derive = total_derive && path_derive;
        total_read = total_read && path_read;
        total_write = total_write && path_write;
    }
    if let Some(prompt) = total_prompt {
        let (resp_tx, resp_rx) = oneshot::channel();
        fg_tx.try_send(B2F::Prompt(B2FPrompt { prompt_rules: prompt.rules.clone() }, resp_tx))?;
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
        derive: total_derive,
        read: total_read,
        write: total_write,
    });
}
