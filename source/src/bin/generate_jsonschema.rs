use {
    passworth::{
        config::Config,
        proto,
    },
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
    write(
        root.join("proto.schema.json"),
        serde_json::to_vec_pretty(&schema_for!(proto::msg::Req)).unwrap(),
    ).unwrap();
    {
        use passworth::proto::*;

        macro_rules! write_resp{
            ($r: ty) => {
                write(
                    root.join(format!("proto_{}_resp.schema.json", stringify!($r))),
                    serde_json::to_vec_pretty(&schema_for!(<$r as msg:: ReqTrait >:: Resp)).unwrap(),
                ).unwrap();
            };
        }

        write_resp!(ReqUnlock);
        write_resp!(ReqLock);
        write_resp!(ReqGet);
        write_resp!(ReqSet);
        write_resp!(ReqMove);
        write_resp!(ReqGenerate);
        write_resp!(ReqPgpSign);
        write_resp!(ReqPgpDecrypt);
        write_resp!(ReqGetRevisions);
        write_resp!(ReqRevert);
    }
}
