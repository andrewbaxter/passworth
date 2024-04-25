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
                        "create table \"config\" ( \"data\" text not null , \"unique\" integer not null , constraint \"config_unique\" primary key ( \"unique\" ) )";
                    txn.execute(query, ()).to_good_error_query(query)?
                };
                {
                    let query =
                        "create table \"factor_state\" ( \"id\" text not null , \"state\" blob not null , constraint \"factor_id\" primary key ( \"id\" ) )";
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

pub fn config_set(db: &rusqlite::Connection, data: &passworth::config::Config) -> Result<(), GoodError> {
    let query =
        "insert into \"config\" ( \"unique\" , \"data\" ) values ( 0 , $1 ) on conflict do update set \"data\" = $1";
    db
        .execute(
            query,
            rusqlite::params![
                <passworth::config::Config as good_ormning_runtime
                ::sqlite
                ::GoodOrmningCustomString<passworth::config::Config>>::to_sql(
                    &data,
                )
            ],
        )
        .to_good_error_query(query)?;
    Ok(())
}

pub fn config_get(db: &rusqlite::Connection) -> Result<Option<passworth::config::Config>, GoodError> {
    let query = "select \"config\" . \"data\" from \"config\" where ( \"config\" . \"unique\" = 0 )";
    let mut stmt = db.prepare(query).to_good_error_query(query)?;
    let mut rows = stmt.query(rusqlite::params![]).to_good_error_query(query)?;
    let r = rows.next().to_good_error(|| format!("Getting row in query [{}]", query))?;
    if let Some(r) = r {
        return Ok(Some({
            let x: String = r.get(0usize).to_good_error(|| format!("Getting result {}", 0usize))?;
            let x =
                <passworth::config::Config as good_ormning_runtime
                ::sqlite
                ::GoodOrmningCustomString<passworth::config::Config>>::from_sql(
                    x,
                ).to_good_error(|| format!("Parsing result {}", 0usize))?;
            x
        }));
    }
    Ok(None)
}

pub fn factor_add(db: &rusqlite::Connection, id: &str, token: &[u8]) -> Result<(), GoodError> {
    let query = "insert into \"factor_state\" ( \"id\" , \"state\" ) values ( $1 , $2 )";
    db.execute(query, rusqlite::params![id, token]).to_good_error_query(query)?;
    Ok(())
}

pub fn factor_delete(db: &rusqlite::Connection, id: &str) -> Result<Option<i32>, GoodError> {
    let query = "delete from \"factor_state\" where ( \"factor_state\" . \"id\" = $1 ) returning 0 as \"ok\"";
    let mut stmt = db.prepare(query).to_good_error_query(query)?;
    let mut rows = stmt.query(rusqlite::params![id]).to_good_error_query(query)?;
    let r = rows.next().to_good_error(|| format!("Getting row in query [{}]", query))?;
    if let Some(r) = r {
        return Ok(Some({
            let x: i32 = r.get(0usize).to_good_error(|| format!("Getting result {}", 0usize))?;
            x
        }));
    }
    Ok(None)
}

pub struct DbRes1 {
    pub id: String,
    pub state: Vec<u8>,
}

pub fn factor_list(db: &rusqlite::Connection) -> Result<Vec<DbRes1>, GoodError> {
    let mut out = vec![];
    let query = "select \"factor_state\" . \"id\" , \"factor_state\" . \"state\" from \"factor_state\"";
    let mut stmt = db.prepare(query).to_good_error_query(query)?;
    let mut rows = stmt.query(rusqlite::params![]).to_good_error_query(query)?;
    while let Some(r) = rows.next().to_good_error(|| format!("Getting row in query [{}]", query))? {
        out.push(DbRes1 {
            id: {
                let x: String = r.get(0usize).to_good_error(|| format!("Getting result {}", 0usize))?;
                x
            },
            state: {
                let x: Vec<u8> = r.get(1usize).to_good_error(|| format!("Getting result {}", 1usize))?;
                x
            },
        });
    }
    Ok(out)
}
