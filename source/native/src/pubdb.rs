use {
    crate::config::UnlockConfig,
    good_ormning::runtime::{
        GoodError,
        sqlite::SqliteConnection,
    },
};

good_ormning::good_module!(pub dbm, "pubdb");

pub fn config_get<C: SqliteConnection>(db: &mut C) -> Result<Option<UnlockConfig>, GoodError> {
    let mut db = dbm::DbPubdb(db);
    Ok(good_ormning::sqlite::good_query_opt!(
        dbm,
        "pubdb",
        //# genemichaels-external: sql-formatter-sqlite
        r#"select
             "config"."data" as "data"
           from
             "config"
           where
             "config"."unique" = 0
           "#;
        &mut db
    )?)
}

pub fn config_set<C: SqliteConnection>(db: &mut C, data: &UnlockConfig) -> Result<(), GoodError> {
    let mut db = dbm::DbPubdb(db);
    good_ormning::sqlite::good_query!(
        dbm,
        "pubdb",
        //# genemichaels-external: sql-formatter-sqlite
        r#"insert into
             "config" ("unique", "data")
           values
             (0, ?1)
           on conflict ("unique") do update
           set
             "data" = ?1
           "#;
        &mut db,
        p1: UnlockConfig = data
    )
}

pub fn factor_add<C: SqliteConnection>(db: &mut C, id: &str, state: &[u8]) -> Result<(), GoodError> {
    let mut db = dbm::DbPubdb(db);
    good_ormning::sqlite::good_query!(
        dbm,
        "pubdb",
        //# genemichaels-external: sql-formatter-sqlite
        r#"insert into
             "factor_state" ("id", "state")
           values
             (?1, ?2)
           "#;
        &mut db,
        p1: string = id,
        p2: bytes = state
    )
}

pub fn factor_delete<C: SqliteConnection>(db: &mut C, id: &str) -> Result<Option<i32>, GoodError> {
    let mut db = dbm::DbPubdb(db);
    Ok(good_ormning::sqlite::good_query_opt!(
        dbm,
        "pubdb",
        //# genemichaels-external: sql-formatter-sqlite
        r#"delete from "factor_state"
           where
             "id" = ?1
           returning
             0 as "ok"
           "#;
        &mut db,
        p1: string = id
    )?)
}

pub fn factor_list<C: SqliteConnection>(db: &mut C) -> Result<Vec<FactorRow>, GoodError> {
    let mut db = dbm::DbPubdb(db);
    let rows = good_ormning::sqlite::good_query_many!(
        dbm,
        "pubdb",
        //# genemichaels-external: sql-formatter-sqlite
        r#"select
             "factor_state"."id" as "id",
             "factor_state"."state" as "state"
           from
             "factor_state"
           "#;
        &mut db
    )?;
    Ok(rows.into_iter().map(|r| FactorRow {
        id: r.id,
        state: r.state,
    }).collect())
}

pub struct FactorRow {
    pub id: String,
    pub state: Vec<u8>,
}

pub fn migrate<C: SqliteConnection>(db: &mut C) -> Result<(), GoodError> {
    let _wrapper = dbm::migrate(db, None)?;
    Ok(())
}
