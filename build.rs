use std::{
    path::PathBuf,
    env,
};
use good_ormning::sqlite::{
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
            eq_field,
            expr_and,
            field_param,
            set_field,
        },
    },
    schema::{
        constraint::{
            ConstraintType,
            PrimaryKeyDef,
        },
        field::{
            field_bytes,
            field_str,
            field_utctime_ms,
            Field,
        },
    },
    types::{
        type_i32,
        SimpleSimpleType,
        SimpleType,
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

        // Config
        {
            let table = latest_version.table("zQLEK3CT0", "configs");
            let rev_id = table.rowid_field(&mut latest_version, None);
            let rev_date = table.field(&mut latest_version, "zM8SEBY6G", "rev_stamp", field_utctime_ms().build());
            let data =
                table.field(
                    &mut latest_version,
                    "zLQI9HQUQ",
                    "data",
                    field_str().custom("passworth::config::Config").build(),
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
                    .group(vec![Expr::LitNull(SimpleType {
                        // Hack to get max to return 0 rows for empty result set
                        type_: SimpleSimpleType::Bool,
                        custom: None,
                    })])
                    .build_query("config_get_latest", QueryResCount::MaybeOne),
            );
        }

        // Factor associated data
        {
            let table = latest_version.table("zDC6NTXMT", "factor");
            let id = table.field(&mut latest_version, "zJ18G7WED", "id", field_str().build());
            let token = table.field(&mut latest_version, "zIPCVSXVU", "enc_token", field_bytes().build());
            table.constraint(
                &mut latest_version,
                "z7NV6BK3R",
                "factor_id",
                ConstraintType::PrimaryKey(PrimaryKeyDef { fields: vec![id.clone()] }),
            );
            methods.push(
                new_insert(
                    &table,
                    vec![set_field("id", &id), set_field("token", &token)],
                ).build_query("factor_add", QueryResCount::None),
            );
            methods.push(
                new_delete(&table)
                    .where_(eq_field("id", &id))
                    .return_named("ok", Expr::LitI32(0))
                    .build_query("factor_delete", QueryResCount::MaybeOne),
            );
            methods.push(
                new_select(&table)
                    .return_field(&id)
                    .return_field(&token)
                    .build_query("factor_list", QueryResCount::Many),
            );
        }

        // Generate
        good_ormning::sqlite::generate(&root.join("src/bin/serverlib/pubdb.rs"), vec![
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
            let value = table.field(&mut latest_version, "zLAPH3H29", "data", field_str().opt().build());
            queries.push(
                new_insert(
                    &table,
                    vec![set_field("stamp", &rev_date), set_field("path", &path), set_field("value", &value)],
                ).build_query("values_insert", QueryResCount::None),
            );
            queries.push(new_select(&table)
                .where_(expr_and(vec![
                    //. .
                    Expr::BinOp {
                        left: Box::new(Expr::Field(path.clone())),
                        op: BinOp::Like,
                        right: Box::new(Expr::Call {
                            func: "format".to_string(),
                            args: vec![Expr::LitString("%s%%".to_string()), field_param("prefix", &path)],
                            compute_type: ComputeType::new(move |_ctx, _path, _args| {
                                return Some(type_i32().build());
                            }),
                        }),
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
                .group(vec![Expr::LitNull(SimpleType {
                    // Hack to get max to return 0 rows for empty result set
                    type_: SimpleSimpleType::Bool,
                    custom: None,
                })])
                .build_query("values_get", QueryResCount::Many));
            queries.push(new_select(&table)
                .where_(expr_and(vec![
                    //. .
                    Expr::BinOp {
                        left: Box::new(Expr::BinOp {
                            left: Box::new(Expr::Field(path.clone())),
                            op: BinOp::Like,
                            right: Box::new(Expr::Call {
                                func: "format".to_string(),
                                args: vec![Expr::LitString("%s%%".to_string()), field_param("prefix", &path)],
                                compute_type: ComputeType::new(move |_ctx, _path, _args| {
                                    return Some(type_i32().build());
                                }),
                            }),
                        }),
                        op: BinOp::Or,
                        right: Box::new(Expr::BinOp {
                            left: Box::new(Expr::Call {
                                func: "instr".to_string(),
                                args: vec![field_param("prefix", &path), Expr::Field(path.clone())],
                                compute_type: ComputeType::new(move |_ctx, _path, _args| {
                                    return Some(type_i32().build());
                                }),
                            }),
                            op: BinOp::Equals,
                            right: Box::new(Expr::LitI32(0)),
                        }),
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
                .group(vec![Expr::LitNull(SimpleType {
                    // Hack to get max to return 0 rows for empty result set
                    type_: SimpleSimpleType::Bool,
                    custom: None,
                })])
                .build_query("values_get_above_below", QueryResCount::Many));
        }

        // Generate
        good_ormning::sqlite::generate(&root.join("src/bin/serverlib/privdb.rs"), vec![
            // Versions
            (0usize, latest_version)
        ], queries).unwrap();
    }
}
