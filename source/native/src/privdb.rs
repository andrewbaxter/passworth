use {
    chrono::{
        DateTime,
        Utc,
    },
    good_ormning::runtime::{
        GoodError,
        sqlite::SqliteConnection,
    },
};

good_ormning::good_module!(pub dbm, "privdb");

pub fn migrate<C: SqliteConnection>(db: &mut C) -> Result<(), GoodError> {
    let _wrapper = dbm::migrate(db, None)?;
    Ok(())
}

pub struct ValueExactRow {
    pub data: String,
    pub rev_id: i64,
}

pub struct ValueRow {
    pub data: String,
    pub path: String,
    pub rev_id: i64,
    pub rev_stamp: DateTime<Utc>,
}

pub fn values_get<C: SqliteConnection>(db: &mut C, path: &str, at: i64) -> Result<Vec<ValueRow>, GoodError> {
    let mut db = dbm::DbPrivdb(db);
    let rows = good_ormning::sqlite::good_query_many!(
        dbm,
        "privdb",
        //# genemichaels-external: sql-formatter-sqlite
        r#"select
             max("values"."rowid") as "rev_id",
             "values"."rev_stamp" as "rev_stamp",
             "values"."path" as "path",
             "values"."data" as "data"
           from
             "values"
           where
             (
               "values"."path" = ?1
               or "values"."path" like(?1 || '/%')
             )
             and "values"."rowid" <= ?2
           group by
             "values"."path"
           order by
             "values"."rev_stamp" asc
           "#;
        &mut db,
        p1: string = path,
        p2: i64 = at
    )?;
    Ok(rows.into_iter().map(|r| ValueRow {
        rev_id: r.rev_id.unwrap_or(0),
        rev_stamp: r.rev_stamp,
        path: r.path,
        data: r.data,
    }).collect())
}

pub fn values_get_exact<
    C: SqliteConnection,
>(db: &mut C, path: &str, at: i64) -> Result<Option<ValueExactRow>, GoodError> {
    let mut db = dbm::DbPrivdb(db);
    Ok(good_ormning::sqlite::good_query_opt!(
        dbm,
        "privdb",
        //# genemichaels-external: sql-formatter-sqlite
        r#"select
             max("values"."rowid") as "rev_id",
             "values"."data" as "data"
           from
             "values"
           where
             "values"."path" = ?1
             and "values"."rowid" <= ?2
           group by
             "values"."path"
           "#;
        &mut db,
        p1: string = path,
        p2: i64 = at
    )?.map(|r| ValueExactRow {
        rev_id: r.rev_id.unwrap_or(0),
        data: r.data,
    }))
}

pub fn values_insert<
    C: SqliteConnection,
>(db: &mut C, stamp: DateTime<Utc>, path: &str, value: &str) -> Result<(), GoodError> {
    let mut db = dbm::DbPrivdb(db);
    good_ormning::sqlite::good_query!(
        dbm,
        "privdb",
        //# genemichaels-external: sql-formatter-sqlite
        r#"insert into
             "values" ("rev_stamp", "path", "data")
           values
             (?1, ?2, ?3)
           "#;
        &mut db,
        p1: utctime_ms_chrono = stamp,
        p2: string = path,
        p3: string = value
    )
}
