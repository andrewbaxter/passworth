use {
    good_ormning::sqlite::{
        new_delete,
        new_insert,
        new_select,
        query::{
            expr::{
                BinOp,
                ComputeType,
                Expr,
            },
            helpers::{
                expr_and,
                expr_field_eq,
                expr_field_lte,
                field_param,
                set_field,
            },
            select_body::Order,
        },
        schema::{
            constraint::{
                ConstraintType,
                PrimaryKeyDef,
            },
            field::{
                field_bytes,
                field_i32,
                field_str,
                field_utctime_ms,
                Field,
            },
        },
        types::type_str,
        QueryResCount,
        Version,
    },
    std::{
        env,
        path::PathBuf,
    },
};

fn expr_max(field: &Field) -> Expr {
    let type_ = field.type_.type_.clone();
    return Expr::Call {
        func: "max".to_string(),
        args: vec![Expr::field(&field)],
        compute_type: ComputeType::new(move |_ctx, _path, _args| {
            return Some(type_.clone());
        }),
    };
}

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    let out = PathBuf::from(&env::var("OUT_DIR").unwrap());

    // Unencrypted
    {
        let mut latest_version = Version::default();
        let mut methods = vec![];

        // Config
        {
            let table = latest_version.table("zQLEK3CT0", "config");
            let unique = table.field(&mut latest_version, "zBI7DOV9J", "unique", field_i32().build());
            let data =
                table.field(
                    &mut latest_version,
                    "zLQI9HQUQ",
                    "data",
                    field_str().custom("passworth::config::Config").build(),
                );
            table.constraint(
                &mut latest_version,
                "zA3Q776DD",
                "config_unique",
                ConstraintType::PrimaryKey(PrimaryKeyDef { fields: vec![unique.clone()] }),
            );
            methods.push(
                new_insert(&table, vec![(unique.clone(), Expr::LitI32(0)), set_field("data", &data)])
                    .on_conflict(
                        good_ormning::sqlite::query::insert::InsertConflict::DoUpdate(vec![set_field("data", &data)]),
                    )
                    .build_query("config_set", QueryResCount::None),
            );
            methods.push(new_select(&table).where_(Expr::BinOp {
                left: Box::new(Expr::field(&unique)),
                op: BinOp::Equals,
                right: Box::new(Expr::LitI32(0)),
            }).return_field(&data).build_query("config_get", QueryResCount::MaybeOne));
        }

        // Factor associated data
        {
            let table = latest_version.table("zDC6NTXMT", "factor_state");
            let id = table.field(&mut latest_version, "zJ18G7WED", "id", field_str().build());
            let state = table.field(&mut latest_version, "zIPCVSXVU", "state", field_bytes().build());
            table.constraint(
                &mut latest_version,
                "z7NV6BK3R",
                "factor_id",
                ConstraintType::PrimaryKey(PrimaryKeyDef { fields: vec![id.clone()] }),
            );
            methods.push(
                new_insert(
                    &table,
                    vec![set_field("id", &id), set_field("token", &state)],
                ).build_query("factor_add", QueryResCount::None),
            );
            methods.push(
                new_delete(&table)
                    .where_(expr_field_eq("id", &id))
                    .return_named("ok", Expr::LitI32(0))
                    .build_query("factor_delete", QueryResCount::MaybeOne),
            );
            methods.push(
                new_select(&table)
                    .return_field(&id)
                    .return_field(&state)
                    .build_query("factor_list", QueryResCount::Many),
            );
        }

        // Generate
        good_ormning::sqlite::generate(&out.join("pubdb.rs"), vec![
            // Versions
            (0usize, latest_version)
        ], methods).unwrap();
    }

    // Encrypted
    {
        let mut latest_version = Version::default();
        let mut queries = vec![];

        // Pass values
        {
            let table = latest_version.table("zQLEK3CT0", "values");
            let rev_id = table.rowid_field(&mut latest_version, None);
            let rev_date = table.field(&mut latest_version, "zG4QTFY3G", "rev_stamp", field_utctime_ms().build());
            let path = table.field(&mut latest_version, "zLQI9HQUQ", "path", field_str().build());
            let value = table.field(&mut latest_version, "zLAPH3H29", "data", field_str().build());
            queries.push(
                new_insert(
                    &table,
                    vec![set_field("stamp", &rev_date), set_field("path", &path), set_field("value", &value)],
                ).build_query("values_insert", QueryResCount::None),
            );
            queries.push(
                new_select(&table)
                    .where_(expr_and(vec![
                        //. .
                        Expr::BinOpChain {
                            op: BinOp::Or,
                            exprs: vec![
                                //. .
                                expr_field_eq("path", &path),
                                Expr::BinOp {
                                    left: Box::new(Expr::field(&path)),
                                    op: BinOp::Like,
                                    right: Box::new(Expr::Call {
                                        func: "format".to_string(),
                                        args: vec![Expr::LitString("%s/%%".to_string()), field_param("path", &path)],
                                        compute_type: ComputeType::new(move |_ctx, _path, _args| {
                                            return Some(type_str().build());
                                        }),
                                    }),
                                }
                            ],
                        },
                        expr_field_lte("at", &rev_id)
                    ]))
                    .group(vec![Expr::field(&path)])
                    .return_named("rev_id", expr_max(&rev_id))
                    .return_field(&rev_date)
                    .return_field(&path)
                    .return_field(&value)
                    .order(Expr::field(&rev_date), Order::Asc)
                    .build_query("values_get", QueryResCount::Many),
            );
            queries.push(
                new_select(&table)
                    .where_(expr_and(vec![
                        //. .
                        expr_field_eq("path", &path),
                        expr_field_lte("at", &rev_id)
                    ]))
                    .group(vec![Expr::field(&path)])
                    .return_named("rev_id", expr_max(&rev_id))
                    .return_field(&value)
                    .build_query("values_get_exact", QueryResCount::MaybeOne),
            );
        }

        // Generate
        good_ormning::sqlite::generate(&out.join("privdb.rs"), vec![
            // Versions
            (0usize, latest_version)
        ], queries).unwrap();
    }
}
