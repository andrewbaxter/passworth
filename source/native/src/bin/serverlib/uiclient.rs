//! Drives the `passworth-ui` helper process. See `passworth_native::uiproto` for the
//! protocol. One helper process is started per user-facing operation (unlock,
//! initialize, prompt) and killed when it's done, so GTK never runs in the server
//! process and each interaction gets a fresh helper.
use {
    loga::{
        DebugDisplay,
        ErrContext,
        Log,
        ResultContext,
        conversion::ResultIgnore,
        ea,
    },
    passworth_native::uiproto::{
        Body,
        FromUi,
        Title,
        ToUi,
        UiValue,
    },
    std::{
        collections::HashMap,
        path::PathBuf,
        process::Stdio,
        sync::{
            Arc,
            Mutex,
            atomic::{
                AtomicU64,
                Ordering,
            },
        },
    },
    tokio::{
        io::{
            AsyncBufReadExt,
            AsyncWriteExt,
            BufReader,
        },
        process::{
            Child,
            Command,
        },
        sync::{
            mpsc,
            oneshot,
        },
    },
};

#[derive(Clone)]
pub struct UiSpawnConfig {
    pub binary: PathBuf,
    /// Run as this uid/gid with this home directory.
    pub run_as: Option<(u32, u32, PathBuf)>,
    pub env: HashMap<String, String>,
}

pub struct UiClient {
    _child: Child,
    out_tx: mpsc::UnboundedSender<ToUi>,
    pending: Arc<Mutex<HashMap<u64, oneshot::Sender<Option<UiValue>>>>>,
    next_id: AtomicU64,
}

impl UiClient {
    pub async fn spawn(log: &Log, config: &UiSpawnConfig) -> Result<UiClient, loga::Error> {
        let mut cmd = Command::new(&config.binary);
        cmd.stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::inherit()).kill_on_drop(true);
        for (k, v) in &config.env {
            cmd.env(k, v);
        }
        if let Some((uid, gid, home)) = &config.run_as {
            cmd.uid(*uid).gid(*gid);
            cmd.env("HOME", home);
            if !config.env.contains_key("XDG_RUNTIME_DIR") {
                cmd.env("XDG_RUNTIME_DIR", format!("/run/user/{}", uid));
            }
            unsafe {
                cmd.pre_exec(|| {
                    // Drop the server's supplementary groups too
                    if libc::setgroups(0, std::ptr::null()) != 0 {
                        return Err(std::io::Error::last_os_error());
                    }
                    return Ok(());
                });
            }
        }
        let mut child =
            cmd.spawn().context_with("Error starting UI helper process", ea!(binary = config.binary.dbg_str()))?;
        let stdin = child.stdin.take().unwrap();
        let stdout = child.stdout.take().unwrap();

        // Writer
        let (out_tx, mut out_rx) = mpsc::unbounded_channel::<ToUi>();
        tokio::spawn({
            let log = log.clone();
            async move {
                let mut stdin = stdin;
                while let Some(m) = out_rx.recv().await {
                    let mut line = serde_json::to_vec(&m).unwrap();
                    line.push(b'\n');
                    if let Err(e) = stdin.write_all(&line).await {
                        log.log_err(loga::DEBUG, e.context("Error writing to UI helper"));
                        break;
                    }
                    if let Err(e) = stdin.flush().await {
                        log.log_err(loga::DEBUG, e.context("Error flushing UI helper input"));
                        break;
                    }
                }
            }
        });

        // Reader
        let pending = Arc::new(Mutex::new(HashMap::<u64, oneshot::Sender<Option<UiValue>>>::new()));
        tokio::spawn({
            let pending = pending.clone();
            let log = log.clone();
            async move {
                let mut lines = BufReader::new(stdout).lines();
                loop {
                    match lines.next_line().await {
                        Ok(Some(line)) => {
                            let msg = match serde_json::from_str::<FromUi>(&line) {
                                Ok(m) => m,
                                Err(e) => {
                                    log.log_err(
                                        loga::WARN,
                                        e.context_with("Invalid message from UI helper", ea!(line = line)),
                                    );
                                    continue;
                                },
                            };
                            let (id, value) = match msg {
                                FromUi::Result { id, value } => (id, Some(value)),
                                FromUi::Cancelled { id } => (id, None),
                            };
                            if let Some(tx) = pending.lock().unwrap().remove(&id) {
                                tx.send(value).ignore();
                            }
                        },
                        Ok(None) => break,
                        Err(e) => {
                            log.log_err(loga::WARN, e.context("Error reading from UI helper"));
                            break;
                        },
                    }
                }

                // Helper gone; anything still waiting gets an error (sender dropped)
                pending.lock().unwrap().clear();
            }
        });
        return Ok(UiClient {
            _child: child,
            out_tx: out_tx,
            pending: pending,
            next_id: AtomicU64::new(1),
        });
    }

    /// Open a window. Dropping the returned handle before it's answered closes the
    /// window.
    pub fn open(&self, title: Title, error: Option<String>, body: Body) -> UiWindow<'_> {
        let id = self.next_id.fetch_add(1, Ordering::SeqCst);
        let (tx, rx) = oneshot::channel();
        self.pending.lock().unwrap().insert(id, tx);
        self.out_tx.send(ToUi::Open {
            id: id,
            title: title,
            error: error,
            body: body,
        }).ignore();
        return UiWindow {
            client: self,
            id: id,
            rx: Some(rx),
            finished: false,
        };
    }
}

pub struct UiWindow<'a> {
    client: &'a UiClient,
    id: u64,
    rx: Option<oneshot::Receiver<Option<UiValue>>>,
    finished: bool,
}

impl<'a> UiWindow<'a> {
    /// `Ok(None)` means the user cancelled. `Err` means the helper process went away.
    pub async fn wait(&mut self) -> Result<Option<UiValue>, loga::Error> {
        let Some(rx) = self.rx.as_mut() else {
            return Err(loga::err("UI window already finished"));
        };
        let r = rx.await;
        self.finished = true;
        self.rx = None;
        match r {
            Ok(v) => return Ok(v),
            Err(_) => return Err(loga::err("UI helper process exited unexpectedly")),
        }
    }
}

impl<'a> Drop for UiWindow<'a> {
    fn drop(&mut self) {
        if !self.finished {
            self.client.pending.lock().unwrap().remove(&self.id);
            self.client.out_tx.send(ToUi::Close { id: self.id }).ignore();
        }
    }
}
