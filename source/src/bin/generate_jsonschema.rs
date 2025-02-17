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

        write_resp!(ReqLock);
        write_resp!(ReqMetaKeys);
        write_resp!(ReqMetaRevisions);
        write_resp!(ReqMetaPgpPubkey);
        write_resp!(ReqMetaSshPubkey);
        write_resp!(ReqRead);
        write_resp!(ReqWrite);
        write_resp!(ReqWriteGenerate);
        write_resp!(ReqWriteMove);
        write_resp!(ReqWriteRevert);
        write_resp!(ReqDerivePgpSign);
        write_resp!(ReqDerivePgpDecrypt);
        write_resp!(ReqDeriveOtp);
    }
}
