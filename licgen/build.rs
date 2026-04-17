use std::env;
use std::fs;
use std::path::PathBuf;

fn main() {
    let crate_dir = env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR is not set");
    let out_dir = PathBuf::from(&crate_dir).join("include");
    let header_path = out_dir.join("licgen.h");

    fs::create_dir_all(&out_dir).expect("failed to create include directory");

    cbindgen::Builder::new()
        .with_crate(crate_dir)
        .with_config(cbindgen::Config::from_file("cbindgen.toml").expect("failed to read cbindgen.toml"))
        .generate()
        .expect("failed to generate C header with cbindgen")
        .write_to_file(header_path);
}

