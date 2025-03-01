use {
    aargvark::{
        vark,
        Aargvark,
    },
    std::path::PathBuf,
    wasm_bindgen_cli_support::Bindgen,
};

#[derive(Aargvark)]
struct Args {
    #[vark(flag = "--in_wasm")]
    in_wasm: PathBuf,
    #[vark(flag = "--out_name")]
    out_name: String,
    #[vark(flag = "--out_dir")]
    out_dir: PathBuf,
}

fn main() {
    let args = vark::<Args>();
    let mut b = Bindgen::new();
    b.input_path(args.in_wasm);
    b.web(true).unwrap();
    b.split_linked_modules(true);
    b.out_name(&args.out_name);
    b.generate(args.out_dir).unwrap();
}
