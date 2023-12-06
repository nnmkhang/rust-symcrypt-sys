use std::env;
use std::path::Path;
use std::fs;
fn main() {
    let dll_path = "inc/symcrypttestmodule.dll";

    // Specify the output directory where the DLL should be copied
    let out_dir = env::var("OUT_DIR").unwrap();
    let dest_path = Path::new(&out_dir).join("symcrypttestmodule.dll");

    // Copy the DLL to the output directory
    fs::copy(&dll_path, &dest_path).expect("Failed to copy DLL");

    // Print a message to inform where the DLL is copied
    println!("cargo:rerun-if-changed={}", dll_path);
    println!("cargo:rerun-if-env-changed=SYMCRYPT_DLL_PATH");
    println!("cargo:rerun-if-env-changed=OUT_DIR");

    // Print an environment variable to let the dependent crates know where the DLL is located
    println!("cargo:rustc-env=SYMCRYPT_DLL_PATH={}", dest_path.display());
    // This will set a directory to be set to the root of the symcrypt-sys crate. This is to get relative paths to find
    // the symcrypttestmodule.lib file.
}