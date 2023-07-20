pub fn init() {
    unsafe {
        symcrypt_sys::SymCryptModuleInit(
            symcrypt_sys::SYMCRYPT_CODE_VERSION_API,
            symcrypt_sys::SYMCRYPT_CODE_VERSION_MINOR,
        );
    }
}

pub mod chacha;
pub mod gcm;
pub mod hash;
pub mod hmac;
pub mod errors;
