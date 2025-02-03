use {
    passworth::config::Config,
    schemars::schema_for,
    std::{
        env,
        fs::{
            create_dir_all,
            write,
        },
        path::PathBuf,
    },
};

fn main() {
    let root = PathBuf::from(&env::var("CARGO_MANIFEST_DIR").unwrap()).join("generated/jsonschema");
    create_dir_all(&root).unwrap();
    write(root.join("config.schema.json"), serde_json::to_vec_pretty(&schema_for!(Config)).unwrap()).unwrap();
}
