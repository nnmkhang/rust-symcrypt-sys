use std::env;
use std::path::Path;
use std::fs;

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
        // This will be something like: C:/your-project/target/debug/

        // you can also set your PATH environment variable to include the symcrypt-sys/inc/ path.
        // Example: $env:PATH = "C:\Code\rust-symcrypt-sys\rust-symcrypt\inc;$env:PATH"
        // Note: This will only work inside the current process. Once the powershell window is closed you must re run the command.

        // Note: This process is a band-aid. Long-term SymCrypt will be shipped with Windows which will make this process much more
        // streamlined. 

    }

    #[cfg(target_os = "linux")]
    {
        println!("cargo:rustc-link-lib=dylib=symcrypt"); // the lib prefix for libsymcrypt is implied on linux

        // Linux based systems use a .so file format that is different from the .lib and .dll format on Windows.
        // TODO: Create a script that copies all libsymcrypt.so* files from SymCrypt path to /lib/x86_64-linux-gnu/
        // The ld linker will look for the symcrypt.so files within /lib/x86_64-linux-gnu/. No need to set a hardcoded path.
        // This is not needed on Mariner as it comes with SymCrypt out of the box. SymCrypt team will work to create a SymCrypt
        // package that will be available via apt get which will install the symcrypt.so files to /lib/x86_64-linux-gnu
    }
}
