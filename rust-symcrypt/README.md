
# SymCrypt Rust Wrapper

This crate provides friendly and idiomatic Rust wrappers over [SymCrypt](https://github.com/microsoft/SymCrypt), an open-source cryptographic library.

This crate has a dependency on `symcrypt-sys`, which utilizes `bindgen` to create Rust/C FFI bindings.

## Dll Setup

### Get symcryptestmodule.dll

To use the SymCrypt crate, you must have a `symcrypttestmodule.dll` on your machine and Windows must be able to find it during runtime. You can obtain this `dll` by installing and building [SymCrypt](https://github.com/microsoft/SymCrypt/blob/main/BUILD.md) yourself. For ease of use, a `symcrypttestmodule.dll` will be included in this repository.


### Make symcrypttestmodule.dll findable


During runtime, Windows will handle finding all needed `dll`'s in order to run the intended program, this includes our `symcrypttestmodule.dll` file. The places Windows will look are:


1. The folder from which the application loaded.
2. The system folder. Use the `GetSystemDirectory` function to retrieve the path of this folder.
3. The Windows folder. Use the `GetWindowsDirectory` function to get the path of this folder.
4. The current folder.
5. The directories listed in the PATH environment variable.

For more info please see: https://learn.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order

Here are some recommended options to ensure your `symcrypttestmodule.dll` is found.

1. The least invasive option is to put it in the same folder as your output `.exe` file. If you are doing development (not release), the common path will be: `C:/your-project/target/debug/`.

2. Alternatively, you can set your PATH environment variable to include the `symcrypt-sys/lib/` path. Example (PowerShell):
	```powershell
	$env:PATH = "C:\Code\rust-symcrypt-sys\rust-symcrypt\lib;$env:PATH"
	```
	**Note:** This change will only persist within the current process, and you must re-set the PATH environment variable after closing the PowerShell window.

3. The easiest option is to manually copy your `symcrypttestmodule.dll` into your `C:/Windows/System32/` folder path. Windows will always search this path for `.dll` files. All future development using `symcrypttestmodule.dll` on your machine will also search the `C:/Windows/System32` path.

**Note:** This process is a short-term solution for Alpha testing. The long-term plan is to have a `symcrypt.dll` shipped with Windows, streamlining the process. In the short term, we are using `symcrypttestmodule.dll` as a workaround.

To test that your `symcrypttestmodule.dll` is working correctly, and that Windows is able to find it,  copy it to your `symcrypt/target/debug/deps/` folder, and run `cargo test` on the SymCrypt crate.

## Supported APIs

### Currently we support the following APIs from SymCrypt:
Hashing:
- Sha256 ( statefull/stateless )
- Sha384 ( statefull/stateless )

HMAC:
- HmacSha256 ( statefull/stateless )
- HmacSha384 ( statefull/stateless )

GCM:
- Encryption ( in place )
- Decryption ( in place )

ChaCha:
- Encryption ( in place )
- Decryption ( in place )

ECDH:
- ECDH Secret Agreement

## Usage
There are unit tests attached to each file that show how to use each function. Included is some sample code to do a stateless Sha256 hash. `symcrypt_init()` must be run before any other calls to the underlying symcrypt code.

**Note:** This code snippet also uses the [hex](https://crates.io/crates/hex) crate.

### Instructions:  

add symcrypt to your `Cargo.toml` file.

```rust
symcrypt = "0.1.0"
```

include symcrypt in your code  

```rust
use symcrypt::hash::sha256; 
use symcrpt::symcrypt_init;
fn  main() {
    symcrpyt_init();
    let data = hex::decode("641ec2cf711e").unwrap();
    let expected: &str = "cfdbd6c9acf9842ce04e8e6a0421838f858559cf22d2ea8a38bd07d5e4692233";

    let result = sha256(&data);
    assert_eq!(hex::encode(result), expected);
}
```