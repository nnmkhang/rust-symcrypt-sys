extern crate bindgen;
extern crate pkg_config;
use std::fs;


use std::env;
use std::path::PathBuf;

fn main() {


    #[cfg(target_os = "windows")] 
    {
        println!("cargo:rustc-link-search=native=D:/rust/pfx_leak/rust-symcrypt-sys/symcypt-sys/inc");
        println!("cargo:libdir=./inc");
        println!("cargo:rustc-link-lib=dylib=symcrypttestmodule"); // test module used in lieu of official symcrypt dll
        fs::copy("inc/symcrypttestmodule.dll", "target/debug/symcrypttestmodule.dll").unwrap();
    }
    
    #[cfg(target_os = "linux")]
    {   
        println!("cargo:libdir=./inc");
        println!("cargo:rustc-link-lib=dylib=symcrypt"); // the lib prefix for libsymcrypt is implied on linux

        // TODO: Create a script that copies all libsymcrypt.so* files from SymCrypt path to /lib/x86_64-linux-gnu/
        // The ld linker will look for the symcrypt.so files within /lib/x86_64-linux-gnu/. No need to set a hardcoded path.
        // Need to find windows equivalent, and other common file paths for other target platforms.
    }

    // TODO: Factor out binding generation. Bindgen should only be run manually with updates to underlying SymCrypt code that 
    // we decide to take.

    // TODO: Add whitelist functions

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
