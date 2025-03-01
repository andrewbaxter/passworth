use {
    loga::{
        ea,
        fatal,
        ResultContext,
    },
    passworth::ipc,
    passworth_native::proto::ipc_path,
    tokio::io::{
        AsyncReadExt,
        AsyncWriteExt,
    },
};

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
            let Some(len) = io_opt(stdin.read_u32().await).context("Error reading downstream request length")? else {
                break;
            };
            let mut req_body = vec![];
            req_body.resize(len as usize, 0);
            let Some(_) =
                io_opt(
                    stdin.read_exact(&mut req_body).await,
                ).context("Error reading downstream request body")? else {
                    break;
                };

            // Passworth
            let payload =
                serde_json::from_slice::<ipc::msg::Req>(
                    &req_body,
                ).context_with(
                    "Received invalid JSON from downstream",
                    ea!(message = String::from_utf8_lossy(&req_body)),
                )?;

            // To browser
            let resp_body = upstream.send_req_enum(&payload).await.map_err(loga::err).context("Error making request upstream")?;
            let Some(_) =
                io_opt(
                    stdout.write_u32(resp_body.len() as u32).await,
                ).context("Error writing downstream response length")? else {
                    break;
                };
            let Some(_) =
                io_opt(stdout.write_all(&resp_body).await).context("Error writing downstream response body")? else {
                    break;
                };
        }
        return Ok(());
    }.await {
        Ok(_) => { },
        Err(e) => fatal(e),
    }
}
