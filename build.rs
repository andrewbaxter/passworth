use std::{
    path::PathBuf,
    env,
};
use good_ormning::sqlite::{
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
            field_param,
            set_field,
        },
    },
    schema::field::{
        field_str,
        field_utctime_ms,
        Field,
    },
    QueryResCount,
    Version,
};

fn expr_max(field: &Field) -> Expr {
    let type_ = field.type_.type_.clone();
    return Expr::Call {
        func: "max".to_string(),
        args: vec![Expr::Field(field.clone())],
        compute_type: ComputeType::new(move |_ctx, _path, _args| {
            return Some(type_.clone());
        }),
    };
}

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    let root = PathBuf::from(&env::var("CARGO_MANIFEST_DIR").unwrap());

    // Unencrypted
    {
        let mut latest_version = Version::default();
        let mut methods = vec![];
        {
            let table = latest_version.table("zQLEK3CT0", "configs");
            let rev_id = table.rowid_field(&mut latest_version, None);
            let rev_date = table.field(&mut latest_version, "zM8SEBY6G", "rev_stamp", field_utctime_ms().build());
            let data =
                table.field(
                    &mut latest_version,
                    "zLQI9HQUQ",
                    "data",
                    field_str().custom("super::pubdbtypes::Config").build(),
                );
            methods.push(
                new_insert(
                    &table,
                    vec![set_field("stamp", &rev_date), set_field("data", &data)],
                ).build_query("config_push", QueryResCount::None),
            );
            methods.push(
                new_select(&table)
                    .return_named("rev_id", expr_max(&rev_id))
                    .return_field(&data)
                    .build_query("config_get_latest", QueryResCount::MaybeOne),
            );
        }
        {
            // TODO derived creds (pub keys)
        }
        good_ormning::sqlite::generate(&root.join("src/bin/serverlib/pubdb.rs"), vec![
            // Versions
            (0usize, latest_version)
        ], methods).unwrap();
    }

    // Encrypted
    {
        let mut latest_version = Version::default();
        let mut queries = vec![];
        {
            let table = latest_version.table("zQLEK3CT0", "values");
            let rev_id = table.rowid_field(&mut latest_version, None);
            let rev_date = table.field(&mut latest_version, "zG4QTFY3G", "rev_stamp", field_utctime_ms().build());
            let path = table.field(&mut latest_version, "zLQI9HQUQ", "path", field_str().build());
            let value = table.field(&mut latest_version, "zLAPH3H29", "points", field_str().build());
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
                        Expr::BinOp {
                            left: Box::new(Expr::Field(path.clone())),
                            op: BinOp::Like,
                            right: Box::new(field_param("prefix", &path)),
                        },
                        Expr::BinOp {
                            left: Box::new(Expr::Field(rev_id.clone())),
                            op: BinOp::LessThan,
                            right: Box::new(field_param("at", &rev_id)),
                        }
                    ]))
                    .group(vec![Expr::Field(path.clone())])
                    .return_named("rev_id", expr_max(&rev_id))
                    .return_field(&rev_date)
                    .return_field(&path)
                    .return_field(&value)
                    .build_query("values_get", QueryResCount::Many),
            );
        }
        good_ormning::sqlite::generate(&root.join("src/bin/serverlib/privdb.rs"), vec![
            // Versions
            (0usize, latest_version)
        ], queries).unwrap();
    }
}
