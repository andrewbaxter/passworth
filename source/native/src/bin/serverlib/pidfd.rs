use {
    loga::{
        ea,
        ResultContext,
    },
    std::{
        os::fd::OwnedFd,
        path::Path,
    },
    tokio::{
        io::unix::AsyncFd,
        task::spawn_blocking,
    },
};

#[derive(Hash, PartialEq, Eq, PartialOrd, Ord, Clone, Copy)]
pub struct Inode(pub u64);

pub async fn pidfd(pid: i32) -> Result<(Inode, AsyncFd<OwnedFd>), loga::Error> {
    return Ok(
        spawn_blocking(move || {
            let pid = rustix::termios::Pid::from_raw(pid).context("Found PID is not a valid PID (not positive)")?;
            let pidfd =
                rustix::process::pidfd_open(
                    pid,
                    rustix::process::PidfdFlags::NONBLOCK,
                ).context("Error opening pidfd")?;
            let pidfd_inode =
                Inode(
                    rustix::fs::statx(
                        &pidfd,
                        Path::new(""),
                        rustix::fs::AtFlags::EMPTY_PATH,
                        rustix::fs::StatxFlags::INO,
                    )
                        .context("Error statxing pidfd for process")?
                        .stx_ino,
                );
            let pidfd = AsyncFd::new(pidfd).context("Error converting pidfd to asyncfd")?;
            return Ok((pidfd_inode, pidfd)) as Result<_, loga::Error>;
        })
            .await
            .context_with("Error waiting for pidfd access worker thread", ea!(pid = pid))?
            .context_with("Unable to access pidfd", ea!(pid = pid))?,
    );
}
