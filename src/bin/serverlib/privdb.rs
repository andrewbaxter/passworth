use good_ormning_runtime::GoodError;
use good_ormning_runtime::ToGoodError;

pub fn migrate(db: &mut rusqlite::Connection) -> Result<(), GoodError> {
    {
        let query =
            "create table if not exists __good_version (rid int primary key, version bigint not null, lock int not null);";
        db.execute(query, ()).to_good_error_query(query)?;
    }
    {
        let query = "insert into __good_version (rid, version, lock) values (0, -1, 0) on conflict do nothing;";
        db.execute(query, ()).to_good_error_query(query)?;
    }
    loop {
        let txn = db.transaction().to_good_error(|| "Starting transaction".to_string())?;
        match (|| {
            let query = "update __good_version set lock = 1 where rid = 0 and lock = 0 returning version";
            let mut stmt = txn.prepare(query).to_good_error_query(query)?;
            let mut rows = stmt.query(()).to_good_error_query(query)?;
            let version = match rows.next().to_good_error_query(query)? {
                Some(r) => {
                    let ver: i64 = r.get(0usize).to_good_error_query(query)?;
                    ver
                },
                None => return Ok(false),
            };
            drop(rows);
            stmt.finalize().to_good_error_query(query)?;
            if version > 0i64 {
                return Err(
                    GoodError(
                        format!(
                            "The latest known version is {}, but the schema is at unknown version {}",
                            0i64,
                            version
                        ),
                    ),
                );
            }
            if version < 0i64 {
                {
                    let query =
                        "create table \"values\" ( \"path\" text not null , \"data\" text , \"rev_stamp\" text not null )";
                    txn.execute(query, ()).to_good_error_query(query)?
                };
            }
            let query = "update __good_version set version = $1, lock = 0";
            txn.execute(query, rusqlite::params![0i64]).to_good_error_query(query)?;
            let out: Result<bool, GoodError> = Ok(true);
            out
        })() {
            Err(e) => {
                match txn.rollback() {
                    Err(e1) => {
                        return Err(
                            GoodError(
                                format!("{}\n\nRolling back the transaction due to the above also failed: {}", e, e1),
                            ),
                        );
                    },
                    Ok(_) => {
                        return Err(e);
                    },
                };
            },
            Ok(migrated) => {
                match txn.commit() {
                    Err(e) => {
                        return Err(GoodError(format!("Error committing the migration transaction: {}", e)));
                    },
                    Ok(_) => {
                        if migrated {
                            return Ok(())
                        } else {
                            std::thread::sleep(std::time::Duration::from_millis(5 * 1000));
                        }
                    },
                };
            },
        }
    }
}

pub fn values_insert(
    db: &rusqlite::Connection,
    stamp: chrono::DateTime<chrono::Utc>,
    path: &str,
    value: Option<&str>,
) -> Result<(), GoodError> {
    let query = "insert into \"values\" ( \"rev_stamp\" , \"path\" , \"data\" ) values ( $1 , $2 , $3 )";
    db
        .execute(query, rusqlite::params![stamp.to_rfc3339(), path, value.map(|value| value)])
        .to_good_error_query(query)?;
    Ok(())
}

pub struct DbRes1 {
    pub rev_id: i64,
    pub rev_stamp: chrono::DateTime<chrono::Utc>,
    pub path: String,
    pub data: Option<String>,
}

pub fn values_get(db: &rusqlite::Connection, prefix: &str, at: i64) -> Result<Vec<DbRes1>, GoodError> {
    let mut out = vec![];
    let query =
        "select max ( \"values\" . \"rowid\" ) as \"rev_id\" , \"values\" . \"rev_stamp\" , \"values\" . \"path\" , \"values\" . \"data\" from \"values\" where ( ( \"values\" . \"path\" like format ( '%s%%' , $1 ) ) and ( \"values\" . \"rowid\" < $2 ) ) group by null";
    let mut stmt = db.prepare(query).to_good_error_query(query)?;
    let mut rows = stmt.query(rusqlite::params![prefix, at]).to_good_error_query(query)?;
    while let Some(r) = rows.next().to_good_error(|| format!("Getting row in query [{}]", query))? {
        out.push(DbRes1 {
            rev_id: {
                let x: i64 = r.get(0usize).to_good_error(|| format!("Getting result {}", 0usize))?;
                x
            },
            rev_stamp: {
                let x: String = r.get(1usize).to_good_error(|| format!("Getting result {}", 1usize))?;
                let x =
                    chrono::DateTime::<chrono::Utc>::from(
                        chrono::DateTime::<chrono::FixedOffset>::parse_from_rfc3339(
                            &x,
                        ).to_good_error(|| format!("Getting result {}", 1usize))?,
                    );
                x
            },
            path: {
                let x: String = r.get(2usize).to_good_error(|| format!("Getting result {}", 2usize))?;
                x
            },
            data: {
                let x: Option<String> = r.get(3usize).to_good_error(|| format!("Getting result {}", 3usize))?;
                x
            },
        });
    }
    Ok(out)
}

pub fn values_get_above_below(db: &rusqlite::Connection, prefix: &str, at: i64) -> Result<Vec<DbRes1>, GoodError> {
    let mut out = vec![];
    let query =
        "select max ( \"values\" . \"rowid\" ) as \"rev_id\" , \"values\" . \"rev_stamp\" , \"values\" . \"path\" , \"values\" . \"data\" from \"values\" where ( ( ( \"values\" . \"path\" like format ( '%s%%' , $1 ) ) or ( instr ( $1 , \"values\" . \"path\" ) = 0 ) ) and ( \"values\" . \"rowid\" < $2 ) ) group by null";
    let mut stmt = db.prepare(query).to_good_error_query(query)?;
    let mut rows = stmt.query(rusqlite::params![prefix, at]).to_good_error_query(query)?;
    while let Some(r) = rows.next().to_good_error(|| format!("Getting row in query [{}]", query))? {
        out.push(DbRes1 {
            rev_id: {
                let x: i64 = r.get(0usize).to_good_error(|| format!("Getting result {}", 0usize))?;
                x
            },
            rev_stamp: {
                let x: String = r.get(1usize).to_good_error(|| format!("Getting result {}", 1usize))?;
                let x =
                    chrono::DateTime::<chrono::Utc>::from(
                        chrono::DateTime::<chrono::FixedOffset>::parse_from_rfc3339(
                            &x,
                        ).to_good_error(|| format!("Getting result {}", 1usize))?,
                    );
                x
            },
            path: {
                let x: String = r.get(2usize).to_good_error(|| format!("Getting result {}", 2usize))?;
                x
            },
            data: {
                let x: Option<String> = r.get(3usize).to_good_error(|| format!("Getting result {}", 3usize))?;
                x
            },
        });
    }
    Ok(out)
}
