use good_ormning::sqlite::{
    generate,
    schema::field::{
        field_bytes,
        field_i32,
        field_str,
        field_utctime_ms_chrono,
    },
    sqlite_type_str as type_str,
    GenerateArgs,
    Version,
};

fn main() {
    println!("cargo:rerun-if-changed=build.rs");

    // Unencrypted (public) db
    {
        let v = Version::new();

        // Config
        {
            let config = v.table("config");
            let unique = config.field("unique", field_i32().build());
            let unlock_config =
                v
                    .custom_type("UnlockConfig")
                    .rust_type("crate::config::UnlockConfig")
                    .base_type(type_str().build());
            config.field("data", unlock_config.field_type());
            config.primary_key("config_unique", &[&unique]);
        }

        // Factor associated data
        {
            let factor_state = v.table("factor_state");
            let id = factor_state.field("id", field_str().build());
            factor_state.field("state", field_bytes().build());
            factor_state.primary_key("factor_id", &[&id]);
        }
        generate(GenerateArgs {
            db_name: Some("pubdb".to_string()),
            versions: vec![(0usize, v.build())],
            ..Default::default()
        }).unwrap();
    }

    // Encrypted (private) db
    {
        let v = Version::new();

        // Pass values
        {
            let values = v.table("values");
            values.rowid_field(None);
            values.field("rev_stamp", field_utctime_ms_chrono().build());
            values.field("path", field_str().build());
            values.field("data", field_str().build());
        }
        generate(GenerateArgs {
            db_name: Some("privdb".to_string()),
            versions: vec![(0usize, v.build())],
            ..Default::default()
        }).unwrap();
    }
}
