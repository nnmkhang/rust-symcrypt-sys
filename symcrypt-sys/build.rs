use std::env;
use std::path::{Path,PathBuf};

fn main() {
    #[cfg(target_os = "windows")]
    {
        // This will set a directory to be set to the root of the symcrypt-sys crate. This is to get relative paths to find
        // the symcrypttestmodule.lib file. 
        let dir = env::var("CARGO_MANIFEST_DIR").unwrap();

        // Look for the .lib file during link time. We are searching the inc/ path which has been set to be relative to the 
        // project root directory. We are checking in the .lib file to maintain control over future FIPs compliance as well
        // as SymCrypt binding API control.
        println!("cargo:rustc-link-search=native={}", Path::new(&dir).join("inc/").display());

        println!("cargo:rustc-link-lib=dylib=symcrypttestmodule"); // test module to search for in lieu of symcrypt.dll


        // During run time, the OS will handle finding the symcrypttestmodule.dll file. The places Windows will look will be:
        // 1. The folder from which the application loaded.
        // 2. The system folder. Use the GetSystemDirectory function to retrieve the path of this folder.
        // 3. The 16-bit system folder. There's no function that obtains the path of this folder, but it is searched.
        // 4. The Windows folder. Use the GetWindowsDirectory function to get the path of this folder.
        // 5. The current folder.
        // 6. The directories that are listed in the PATH environment variable. 

        // For more info please see: https://learn.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order

        // For the least invasive usage, we suggest putting the symcrypttestmodule.dll inside of same folder as the .exe file.
        // This will be something like: 

        // Note: This process is a band-aid. Long-term SymCrypt will be shipped with Windows which will make this process much more
        // streamlined. 

    }

    #[cfg(target_os = "linux")]
    {
        println!("cargo:rustc-link-lib=dylib=symcrypt"); // the lib prefix for libsymcrypt is implied on linux

        // Linux based systems use a .so file format that is different from the .lib and .dll format on Windows.

        // TODO: Create a script that copies all libsymcrypt.so* files from SymCrypt path to /lib/x86_64-linux-gnu/
        // The ld linker will look for the symcrypt.so files within /lib/x86_64-linux-gnu/. No need to set a hardcoded path.
        // This is not needed on Mariner as it comes with SymCrypt out of the box.
    }

    println!("cargo:libdir=../SymCrypt/inc"); // for .h files, only used for creating the bindings
    println!("cargo:rerun-if-changed=inc/wrapper.h");
    let bindings = bindgen::Builder::default()
        .header("inc/wrapper.h")
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
