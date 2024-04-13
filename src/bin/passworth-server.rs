use std::{
    env,
    fs::File,
    os::{
        fd::{
            FromRawFd,
            IntoRawFd,
        },
        unix::net::UnixStream,
    },
    path::PathBuf,
};
use aargvark::{
    vark,
    Aargvark,
    AargvarkJson,
};
use libc::{
    mlockall,
    MCL_CURRENT,
    MCL_FUTURE,
    MCL_ONFAULT,
};
use loga::{
    ea,
    fatal,
    ErrContext,
    ResultContext,
    StandardFlag,
};
use passworth::{
    ioutil::{
        read_packet,
        write_packet,
        write_packet_bytes,
    },
    proto::{
        C2S,
        DEFAULT_SOCKET,
        ENV_SOCKET,
    },
};
use serde::{
    Deserialize,
    Serialize,
};
use serverlib::{
    pubdb,
    pubdbtypes::Config,
};
use taskmanager::TaskManager;
use tokio::{
    fs::remove_file,
    io::{
        AsyncRead,
        AsyncReadExt,
        AsyncWrite,
        AsyncWriteExt,
    },
    sync::Semaphore,
};

pub mod serverlib;

#[derive(Aargvark)]
struct Args {
    config: AargvarkJson<Config>,
}

async fn main_back(mut fg_read: impl tokio::fs::File, mut fg_write: impl tokio::fs::File) -> Result<(), loga::Error> {
    if mlockall(MCL_CURRENT | MCL_FUTURE | MCL_ONFAULT) != 0 {
        return Err(loga::err("mlockall failed, couldn't prevent memory from paging out"));
    }
    let args = vark::<Args>();
    let config = args.config.value;
    let pubdb_path = config.data_path.join("pub.sqlcipher");
    let mut pubdbc = rusqlite::Connection::open(pubdb_path).unwrap();
    pubdb::migrate(
        &mut pubdbc,
    ).context_with("Error setting up pub database", ea!(path = pubdb_path.to_string_lossy()))?;
    match pubdb::config_get_latest(&pubdbc)? {
        Some(current_config) => {
            for (key, cred_config) in config.creds {
                if current_config.creds.remove(key).is_none() {
                    new_creds.push((key, cred_config));
                }
            }
            for (key, current_cred_config) in current_config.creds {
                delete_creds.push(key);
            }
        },
        None => {
            initialize_creds(config.creds);
        },
    };
    let sock_path = env::var_os(ENV_SOCKET).unwrap_or(DEFAULT_SOCKET.into());
    match remove_file(&sock_path).await {
        Ok(_) => todo!(),
        Err(e) => match e.kind() {
            std::io::ErrorKind::NotFound => { },
            _ => return Err(e.context("Error removing old socket")),
        },
    }
    let sem = Semaphore::new(1);
    tm.critical_stream(
        "Command listen",
        TokioStream(
            tokio::net::UnixListener::bind(
                &sock_path,
            ).context_with(
                "Error binding to socket",
                ea!(path = String::from_utf8_lossy(sock_path.as_encoded_bytes())),
            ),
        ),
        |conn| {
            async move {
                let _serialize = sem.acquire().await?;
                while let Some(req) = read_packet::<C2S>(&mut conn).await? {
                    let resp = match req {
                        C2S::Unlock => todo!(),
                        C2S::Lock => todo!(),
                        C2S::Get { paths, at } => todo!(),
                        C2S::Set(_) => todo!(),
                        C2S::GetRevisions { paths, at } => todo!(),
                        C2S::Revert { paths, at } => todo!(),
                    };
                    write_packet_bytes(&mut conn, resp).await?;
                }
            }
        },
    );
    tm.join(log, StandardFlag::Info);
    return Ok(());
}

fn main_front(mut bg_read: tokio::fs::File, mut bg_write: tokio::fs::File) -> Result<(), loga::Error> {
    glib::spawn_future_local(clone!(@ weak button => async move {
        while let Some(req) = read_packet::<B2F>(&mut bg_read).await? {
            match req { }
        }
    }));
}

fn main2() -> Result<(), loga::Error> {
    let b2f_fds =
        nix::unistd::pipe2(
            nix::fcntl::OFlag::from_bits(libc::O_CLOEXEC).context("Error setting up pipe flags")?,
        ).unwrap();
    let f2b_fds =
        nix::unistd::pipe2(
            nix::fcntl::OFlag::from_bits(libc::O_CLOEXEC).context("Error setting up pipe flags")?,
        ).unwrap();
    match unsafe {
        nix::unistd::fork()
    }.context("Failed to fork fg subprocess")? {
        nix::unistd::ForkResult::Parent { .. } => {
            nix::unistd::close(b2f_fds.1.into_raw_fd());
            nix::unistd::close(f2b_fds.1.into_raw_fd());
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .context("Error setting up async runtime")?
                .block_on(
                    main_back(
                        tokio::fs::File::from_raw_fd(b2f_fds.0.into_raw_fd()),
                        tokio::fs::File::from_raw_fd(f2b_fds.0.into_raw_fd()),
                    ),
                )?
        },
        nix::unistd::ForkResult::Child => {
            nix::unistd::close(b2f_fds.0.into_raw_fd());
            nix::unistd::close(f2b_fds.0.into_raw_fd());
            main_front(
                tokio::fs::File::from_raw_fd(b2f_fds.1.into_raw_fd()),
                tokio::fs::File::from_raw_fd(f2b_fds.1.into_raw_fd()),
            );
        },
    }
    return Ok(());
}

fn main() {
    match main2() {
        Ok(_) => { },
        Err(e) => {
            fatal(e);
        },
    }
}
