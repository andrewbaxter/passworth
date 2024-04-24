use loga::{
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
