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
        println!("cargo:rustc-link-lib=dylib=symcrypttestmodule");
        fs::copy("inc/symcrypttestmodule.dll", "target/debug/symcrypttestmodule.dll").unwrap();
    }
    
    #[cfg(target_os = "linux")]
    {   
        // pkg_config::probe_library("SymCrypt").unwrap(); // need to set version requiremnt, bindgen will create bindings based on specific .h file of SymCrypt.h,
        // without version requiremnt, upstream pkgs could have dependancy issues. Should switch this every year to snap to FIPS compliant build
        println!("cargo:rustc-link-search=native=/home/khang/rust/rust-symcrypt-sys/symcrypt-sys/inc/");
        println!("cargo:libdir=./inc");
        println!("cargo:rustc-link-lib=dylib=symcrypt");
        fs::copy("inc/libsymcrypt.so", "target/debug/libsymcrypt.so").unwrap();
        fs::copy("inc/libsymcrypt.so.103", "target/debug/libsymcrypt.so.103").unwrap();
        fs::copy("inc/libsymcrypt.so.103.1.0", "target/debug/libsymcrypt.so.103.1.0").unwrap();
    }

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
