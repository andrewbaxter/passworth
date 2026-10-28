use {
    libc::c_void,
    loga::{
        ErrContext,
        ResultContext,
        ea,
    },
    rusqlite::{
        Connection,
        Transaction,
    },
    std::path::Path,
    super::privdb,
    tokio::task::spawn_blocking,
};

/// Open the private database with the given sqlcipher key string (either a
/// passphrase or a raw `x'..'` key, see `crypto::db_key`). Fails if the key is wrong
/// (the schema can't be read).
pub fn open_privdb(path: &Path, key: &str) -> Result<Connection, loga::Error> {
    let mut privdbc =
        rusqlite::Connection::open(&path).context_with("Error opening private database", ea!(path = path.to_string_lossy()))?;
    let key = key.as_bytes();
    let res = unsafe {
        libsqlite3_sys::sqlite3_key(privdbc.handle(), key.as_ptr() as *const c_void, key.len() as i32)
    };
    if res != 0 {
        return Err(loga::err_with("Sqlcipher key operation exited with code", ea!(code = res)));
    }
    privdb::migrate(&mut privdbc).context("Error migrating private db")?;
    return Ok(privdbc);
}

/// Run `f` in a transaction on a blocking thread. The connection is handed back so
/// the caller can keep it; it's `None` only if the worker panicked.
pub async fn tx<
    T: 'static + Send,
>(
    mut conn: Connection,
    f: impl 'static + Send + FnOnce(&mut Transaction) -> Result<T, loga::Error>,
) -> (Option<Connection>, Result<T, loga::Error>) {
    match spawn_blocking(move || {
        let res = (|| {
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
        })();
        return (conn, res);
    }).await {
        Ok((conn, res)) => return (Some(conn), res),
        Err(e) => return (None, Err(e.into())),
    }
}

#[cfg(test)]
mod test {
    use {
        super::*,
        passworth_native::crypto::{
            TokenScheme,
            db_key,
        },
    };

    /// The legacy scheme keys the database with a passphrase; the current scheme uses
    /// a raw key. Confirm sqlcipher accepts both through `sqlite3_key`, that rekeying
    /// from one to the other works, and that a wrong key is rejected.
    #[test]
    fn test_rekey_passphrase_to_raw() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("priv.sqlcipher");
        let legacy_token = b"hunter2".to_vec();
        let new_token = [7u8; 32];
        let legacy_key = db_key(TokenScheme::Legacy, &legacy_token);
        let new_key = db_key(TokenScheme::V2, &new_token);
        {
            let mut conn = open_privdb(&path, &legacy_key).unwrap();
            privdb::values_insert(&mut conn, chrono::Utc::now(), "/a", "\"x\"").unwrap();
            let k = new_key.as_bytes();
            let res = unsafe {
                libsqlite3_sys::sqlite3_rekey(conn.handle(), k.as_ptr() as *const c_void, k.len() as i32)
            };
            assert_eq!(res, 0);
        }
        assert!(open_privdb(&path, &legacy_key).is_err(), "old passphrase must no longer open the db");
        assert!(open_privdb(&path, &db_key(TokenScheme::V2, &[8u8; 32])).is_err(), "wrong raw key must fail");
        let mut conn = open_privdb(&path, &new_key).unwrap();
        let rows = privdb::values_get(&mut conn, "", i64::MAX).unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].path, "/a");
    }
}
