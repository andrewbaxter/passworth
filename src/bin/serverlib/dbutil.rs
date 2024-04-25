use std::path::Path;
use libc::c_void;
use loga::{
    ea,
    ErrContext,
    ResultContext,
};
use rusqlite::{
    Connection,
    Transaction,
};
use tokio::task::spawn_blocking;

pub async fn tx<
    T: 'static + Send,
>(
    mut conn: Connection,
    f: impl 'static + Send + FnOnce(&mut Transaction) -> Result<T, loga::Error>,
) -> Result<T, loga::Error> {
    return spawn_blocking(move || {
        let mut txn = conn.transaction()?;
        match f(&mut txn).context("Error performing transaction") {
            Ok(r) => {
                txn.commit().context("Transaction commit failed")?;
                return Ok(r);
            },
            Err(e) => {
                match txn.rollback() {
                    Ok(_) => {
                        return Err(e);
                    },
                    Err(e2) => {
                        return Err(e.also(e2.context("Error rolling back transaction")));
                    },
                }
            },
        }
    }).await?;
}

pub fn open_privdb(path: &Path, token: &str) -> Result<Connection, loga::Error> {
    let privdbc = rusqlite::Connection::open(&path).unwrap();
    let token = token.as_bytes();
    let res = unsafe {
        libsqlite3_sys::sqlite3_key(privdbc.handle(), token.as_ptr() as *const c_void, token.len() as i32)
    };
    if res != 0 {
        return Err(loga::err_with("Sqlcipher key operation exited with code", ea!(code = res)));
    }
    return Ok(privdbc);
}
