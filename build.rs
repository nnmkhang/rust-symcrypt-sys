extern crate bindgen;
use std::fs;


use std::env;
use std::path::PathBuf;

fn main() {

    println!("cargo:rustc-link-search=native=D:/rust/pfx_leak/rust-symcrypt-sys/inc");

    println!("cargo:libdir=./inc");

    println!("cargo:rustc-link-lib=dylib=symcrypttestmodule");
    fs::copy("inc/symcrypttestmodule.dll", "target/debug/symcrypttestmodule.dll").unwrap();


    // Tell cargo to invalidate the built crate whenever the wrapper changes
    println!("cargo:rerun-if-changed=inc/wrapper.h");

    let bindings = bindgen::Builder::default()
        .header("inc/wrapper.h")
        .clang_arg("-v")
        .parse_callbacks(Box::new(bindgen::CargoCallbacks))
        .generate()

        .expect("Unable to generate bindings");

    // Write the bindings to the $OUT_DIR/bindings.rs file.
    let out_path = PathBuf::from(env::var("OUT_DIR").unwrap());
    bindings
        .write_to_file(out_path.join("bindings.rs"))
        .expect("Couldn't write bindings!");
}
