extern crate bindgen;

use std::env;
use std::path::PathBuf;


// TODO TOM:
/// Figure out relative path for the .lib
/// move over the bindgen generation to another file
/// write better documentation regarding this stuff


/// SymCrypt must
fn main() {
    #[cfg(target_os = "windows")]
    {
        //println!("cargo:rustc-link-search=native=C:/Windows/System32/"); // ! Work around, looking for better solution
        println!("cargo:rustc-link-search=native=C:/Code/"); // ! Work around, looking for better solution

        // above is used to link search path, both are happening at link time, this will search for the .lib, the OS will do the run time, this is where the OS will
        // look for the .dll 

        // wen we do cargo test, we do the link, we tell them where to find the lib that needs to be linked to the application
        // after we run cargo test, they will do the linking and then pass over to the OS which will just run an .exe file.

        // todo: need to find a way to link to a relative path. 

        // what we need to do is figure out a way to include a relative path to the .lib, as part of the crate 

        println!("cargo:libdir=../SymCrypt/inc"); // for .h files, only used for creating the bindings
        println!("cargo:rustc-link-lib=dylib=symcrypttestmodule"); // test module used in lieu of official symcrypt dll
                                                                   // this dll will be in Windows/System32. This is to mirror future plans; as symcrypt is planned to ship with windows
                                                                   // symcrypttestmodule* files must be placed in Windows/System32/ as a workaround at the moment.
    }

    #[cfg(target_os = "linux")]
    {
        println!("cargo:libdir=../SymCrypt/inc");
        println!("cargo:rustc-link-lib=dylib=symcrypt"); // the lib prefix for libsymcrypt is implied on linux

        // TODO: Create a script that copies all libsymcrypt.so* files from SymCrypt path to /lib/x86_64-linux-gnu/
        // The ld linker will look for the symcrypt.so files within /lib/x86_64-linux-gnu/. No need to set a hardcoded path.
        // This is not needed on Mariner as it comes with SymCrypt out of the box.
    }

    // Since we are pulling in symcrypt as a submodule, it should be pretty easy to run a vendored build, this would allow us
    // to hard stop at a commit and ensure that there is no discrepancy between build version and header version

    // TODO: Factor out binding generation. Bindgen should only be run manually with updates to underlying SymCrypt code that
    // we decide what to take.
    println!("cargo:rerun-if-changed=/wrapper.h");

    // TODO: Discuss if factoring the .allowlist_functions to another file is better approach

    let bindings = bindgen::Builder::default()
        .header("wrapper.h")
        .clang_arg("-v")
        .parse_callbacks(Box::new(bindgen::CargoCallbacks))
        // ALLOWLIST
        // INIT FUNCTIONS
        .allowlist_function("SymCryptModuleInit")
        .allowlist_var("^(SYMCRYPT_CODE_VERSION.*)$")
        // HASH FUNCTIONS
        .allowlist_function("^(SymCryptSha256.*)$")
        .allowlist_function("^(SymCryptSha384.*)$")
        .allowlist_var("SYMCRYPT_SHA256_RESULT_SIZE")
        .allowlist_var("SYMCRYPT_SHA384_RESULT_SIZE")
        // HMAC FUNCTIONS
        .allowlist_function("^(SymCryptHmacSha256.*)$")
        .allowlist_function("^(SymCryptHmacSha384.*)$")
        // GCM FUNCTIONS
        .allowlist_function("^(SymCryptGcm.*)$")
        .allowlist_function("SymCryptChaCha20Poly1305Encrypt")
        .allowlist_function("SymCryptChaCha20Poly1305Decrypt")
        .allowlist_function("SymCryptTlsPrf1_2ExpandKey")
        .allowlist_function("SymCryptTlsPrf1_2Derive")
        .allowlist_function("SymCryptTlsPrf1_2")
        .allowlist_var("SymCryptAesBlockCipher")
        // HKDF functions
        .allowlist_function("^(SymCryptHkdf.*)$")
        // ECDH Key Agreement
        .allowlist_var("SymCryptEcurveParamsNistP256")
        .allowlist_var("SymCryptEcurveParamsNistP384")
        .allowlist_var("SymCryptEcurveParamsCurve25519")
        .allowlist_var("SYMCRYPT_FLAG_ECKEY_ECDH")
        .allowlist_function("^(SymCryptEcurve.*)$")
        .allowlist_function("^(SymCryptEckey.*)$")
        .allowlist_function("SymCryptEcDhSecretAgreement")
        .allowlist_function("SymCryptSizeofEckeyFromCurve")
        // Utility functions
        .allowlist_function("SymCryptWipe")
        .generate_comments(true)
        .derive_default(true)
        .generate()
        .expect("Unable to generate bindings");

    let out_path = PathBuf::from(env::var("OUT_DIR").unwrap());
    bindings
        .write_to_file(out_path.join("bindings.rs"))
        .expect("Couldn't write bindings!");
}
