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

/// Takes in a rand_length and returns a Vec<u8> with rand_length random bytes
pub fn symcrypt_random(rand_length: u64) -> Vec<u8> {
    let mut random_buffer: Vec<u8> = vec![0; rand_length as usize];
    unsafe {
        // SAFETY: FFI calls
        symcrypt_sys::SymCryptRandom(random_buffer.as_mut_ptr(), rand_length);
    }
    random_buffer
}

pub mod block_ciphers;
pub mod chacha;
pub mod ecdh;
pub mod eckey;
pub mod errors;
pub mod gcm;
pub mod hash;
pub mod hmac;
