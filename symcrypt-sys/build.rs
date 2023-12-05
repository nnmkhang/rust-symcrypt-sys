extern crate bindgen;

use std::env;
use std::path::PathBuf;

fn main() {
    #[cfg(target_os = "windows")]
    {
        println!("cargo:rustc-link-search=native=C:/Windows/System32/"); // ! Work around, looking for better solution
        println!("cargo:libdir=../SymCrypt/inc");
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
    println!("cargo:rerun-if-changed=inc/wrapper.h");

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
        .allowlist_function("^(SymCryptSha(256|384)(?:Init|Append|Result|StateCopy)?)$")
        .allowlist_var("^(SYMCRYPT_(SHA256|SHA384)_RESULT_SIZE$)")
        // HMAC FUNCTIONS
        .allowlist_function("^(SymCryptHmacSha(256|384)(?:ExpandKey|Init|Append|Result|StateCopy)?)$")
        // GCM FUNCTIONS
        .allowlist_function("^(SymCryptGcm(?:ValidateParameters|ExpandKey|Encrypt|Decrypt|Init|StateCopy|AuthPart|DecryptPart|EncryptPart|EncryptFinal|DecryptFinal)?)$")
        .allowlist_function("SymCryptChaCha20Poly1305(Encrypt|Decrypt)")
        .allowlist_function("^SymCryptTlsPrf1_2(?:ExpandKey|Derive)?$")
        .allowlist_var("SymCryptAesBlockCipher")
        // HKDF FUNCTIONS
        .allowlist_function("^(SymCryptHkdf.*)$") // TODO: Tighten bindgen after implementation is complete.
        // ECDH KEY AGREEMENT FUNCTIONS
        .allowlist_function("^SymCryptEcurve(Allocate|Free|SizeofFieldElement)$")
        .allowlist_var("^SymCryptEcurveParams(NistP256|NistP384|Curve25519)$")
        .allowlist_function("^(SymCryptEckey(Allocate|Free|SizeofPublicKey|GetValue|SetRandom|SetValue|SetRandom|))$")
        .allowlist_var("SYMCRYPT_FLAG_ECKEY_ECDH")
        .allowlist_function("SymCryptEcDhSecretAgreement")
        // UTILITY FUNCTIONS
        .allowlist_function("SymCryptWipe")
        .allowlist_function("SymCryptRandom")
        
        .generate_comments(true)
        .derive_default(true)
        .generate()
        .expect("Unable to generate bindings");

    let out_path = PathBuf::from(env::var("OUT_DIR").unwrap());
    bindings
        .write_to_file(out_path.join("bindings.rs"))
        .expect("Couldn't write bindings!");
}
