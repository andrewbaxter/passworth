fn main() {
    println!("cargo:rerun-if-env-changed=PASSWORTH_PSL_PATH");
    if let Ok(p) = std::env::var("PASSWORTH_PSL_PATH") {
        println!("cargo:rerun-if-changed={}", p);
    }
}
