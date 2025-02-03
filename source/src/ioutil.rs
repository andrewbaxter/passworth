use {
    loga::{
        ErrContext,
        ResultContext,
    },
    serde::{
        de::DeserializeOwned,
        Serialize,
    },
    tokio::io::{
        AsyncRead,
        AsyncReadExt,
        AsyncWrite,
        AsyncWriteExt,
    },
};

pub async fn read_packet<R: DeserializeOwned>(mut read: impl Unpin + AsyncRead) -> Option<Result<R, loga::Error>> {
    let len = match read.read_u64().await {
        Ok(l) => l,
        Err(e) => match e.kind() {
            std::io::ErrorKind::BrokenPipe => {
                return None;
            },
            _ => {
                return Some(Err(e.context("Error reading packet length")));
            },
        },
    };
    let mut buf = Vec::new();
    buf.resize(len as usize, 0u8);
    match read.read_exact(&mut buf).await {
        Ok(_) => { },
        Err(e) => match e.kind() {
            std::io::ErrorKind::BrokenPipe => {
                return None;
            },
            _ => {
                return Some(Err(e.context("Error reading packet body")));
            },
        },
    };
    return Some(serde_json::from_slice(&buf).context("Error parsing packet"));
}

pub async fn write_packet_bytes(mut write: impl Unpin + AsyncWrite, body: Vec<u8>) -> Result<(), loga::Error> {
    write.write_u64(body.len() as u64).await.context("Error writing packet length")?;
    write.write_all(&body).await.context("Error writing packet body")?;
    return Ok(());
}

pub async fn write_packet(write: impl Unpin + AsyncWrite, body: impl Serialize) -> Result<(), loga::Error> {
    let body = serde_json::to_vec(&body).unwrap();
    return write_packet_bytes(write, body).await;
}
