use {
    loga::{
        ResultContext,
        ea,
        fatal,
    },
    passworth::ipc,
    passworth_shared_native::proto::ipc_path,
    tokio::io::{
        AsyncReadExt,
        AsyncWriteExt,
    },
};

/// Largest message accepted from the browser. Browsers cap native messages at 1MB
/// so this is generous; it exists so the browser can't force an arbitrary allocation.
const MAX_BROWSER_MESSAGE: u32 = 16 * 1024 * 1024;

fn io_opt<T>(r: Result<T, std::io::Error>) -> Result<Option<T>, loga::Error> {
    match r {
        Ok(r) => return Ok(Some(r)),
        Err(e) => match e.kind() {
            std::io::ErrorKind::BrokenPipe |
            std::io::ErrorKind::ConnectionReset |
            std::io::ErrorKind::ConnectionAborted |
            std::io::ErrorKind::NotConnected |
            std::io::ErrorKind::Interrupted |
            std::io::ErrorKind::UnexpectedEof => {
                return Ok(None);
            },
            _ => {
                return Err(e.into());
            },
        },
    }
}

/// The extension is read-only by design. The server's rules are the real control, but
/// there's no reason to let the browser even ask for anything else.
fn browser_allowed(req: &ipc::msg::Req) -> bool {
    match req {
        ipc::msg::Req::MetaKeys(_) => true,
        ipc::msg::Req::Read(_) => true,
        ipc::msg::Req::DeriveOtp(_) => true,
        _ => false,
    }
}

#[tokio::main(flavor = "current_thread")]
async fn main() {
    match async {
        let mut upstream =
            ipc::msg::Client::new(ipc_path())
                .await
                .map_err(loga::err)
                .context("Error opening upstream connection")?;
        let mut stdin = tokio::io::stdin();
        let mut stdout = tokio::io::stdout();
        loop {
            // From browser
            let mut len = [0u8; 4];
            let Some(_) = io_opt(stdin.read_exact(&mut len).await).context("Error reading downstream request length")? else {
                break;
            };
            let len = u32::from_ne_bytes(len);
            if len > MAX_BROWSER_MESSAGE {
                return Err(loga::err_with("Downstream message too large", ea!(len = len)));
            }
            let mut req_body = vec![0u8; len as usize];
            let Some(_) =
                io_opt(
                    stdin.read_exact(&mut req_body).await,
                ).context("Error reading downstream request body")? else {
                    break;
                };
            let payload =
                serde_json::from_slice::<ipc::msg::Req>(
                    &req_body,
                ).context_with(
                    "Received invalid JSON from downstream",
                    ea!(message = String::from_utf8_lossy(&req_body)),
                )?;

            // Passworth
            let resp_body = if !browser_allowed(&payload) {
                serde_json::to_vec(
                    &glove::Resp::<()>::Err(format!("Request type not permitted from the browser extension")),
                ).unwrap()
            } else {
                match upstream.send_req_enum(&payload).await {
                    Ok(v) => v,
                    Err(e) => serde_json::to_vec(
                        &glove::Resp::<()>::Err(format!("Error making request upstream: {}", e)),
                    ).unwrap(),
                }
            };

            // To browser
            let len = (resp_body.len() as u32).to_ne_bytes();
            let Some(_) =
                io_opt(stdout.write_all(&len).await).context("Error writing downstream response length")? else {
                    break;
                };
            let Some(_) =
                io_opt(stdout.write_all(&resp_body).await).context("Error writing downstream response body")? else {
                    break;
                };
            stdout.flush().await.context("Failed to flush stdout")?;
        }
        return Ok(());
    }.await {
        Ok(_) => { },
        Err(e) => fatal(e),
    }
}
