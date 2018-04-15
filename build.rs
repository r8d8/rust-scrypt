extern crate gcc;
use std::env;
use std::path::PathBuf;

fn main() {
    let out_path = PathBuf::from(env::var("OUT_DIR").unwrap());

    gcc::Build::new()
        .flag("-std=c99")
        .include("ext/scrypt")
        .file("ext/scrypt/crypto_scrypt.c")
        .file("ext/scrypt/crypto_scrypt_smix.c")
        .file("ext/scrypt/sha256.c")
        .file("ext/scrypt/insecure_memzero.c")
        .file("ext/scrypt/warnp.c")
        .compile("libscrypt.a");

    println!(
        "cargo:rustc-link-search=native={}",
        out_path.to_str().unwrap()
    );
    println!("cargo:rustc-link-lib=static=scrypt");
}
