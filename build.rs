extern crate gcc;
use std::env;
use std::path::PathBuf;

fn main() {
    let out_path = PathBuf::from(env::var("OUT_DIR").unwrap());

    gcc::compile_library("libscrypt.a", &["ext/scrypt/crypto_scrypt.c",
        "ext/scrypt/crypto_scrypt_smix.c" , "ext/scrypt/sha256.c",
        "ext/scrypt/insecure_memzero.c", "ext/scrypt/warnp.c"]);
    println!("cargo:rustc-link-search=native={}", out_path.to_str().unwrap());
    println!("cargo:rustc-link-lib=static=scrypt");
}