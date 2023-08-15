pub fn init() {
    unsafe {
        symcrypt_sys::SymCryptModuleInit(
            symcrypt_sys::SYMCRYPT_CODE_VERSION_API,
            symcrypt_sys::SYMCRYPT_CODE_VERSION_MINOR,
        );
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
