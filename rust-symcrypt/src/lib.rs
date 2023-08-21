use std::sync::Once;

/// SymCryptModuleInit() must be called before any other function in the library.
/// .call_once() is used used to ensure that symcrypt_init() is not called across multiple threads.
/// Subsequent calls to symcrypt_init() after the first will not be invoked per .call_once() docs.
pub fn symcrypt_init() {
    static INIT: Once = Once::new();
    unsafe {
        // SAFETY: FFI calls, blocking from being run again.
        INIT.call_once(|| {
            symcrypt_sys::SymCryptModuleInit(
                symcrypt_sys::SYMCRYPT_CODE_VERSION_API,
                symcrypt_sys::SYMCRYPT_CODE_VERSION_MINOR,
            )
        });
    }
}

pub mod block_ciphers;
pub mod chacha;
pub mod curve_type;
pub mod ecdh;
pub mod errors;
pub mod gcm;
pub mod hash;
pub mod hmac;
