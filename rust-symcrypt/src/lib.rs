pub struct SymCryptInit;
impl SymCryptInit {
    pub fn new() {
        unsafe {
            symcrypt_sys::SymCryptModuleInit(
                symcrypt_sys::SYMCRYPT_CODE_VERSION_API,
                symcrypt_sys::SYMCRYPT_CODE_VERSION_MINOR,
            );
        }
    }
}

pub mod hash;
pub mod hmac;
