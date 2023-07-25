use symcrypt_sys;


// WIP still working on this
pub enum BlockCipherType {
    AES(symcrypt_sys::PCSYMCRYPT_BLOCKCIPHER),
}

impl BlockCipherType {
    pub fn new_aes() -> symcrypt_sys::PCSYMCRYPT_BLOCKCIPHER {
        let aes_cipher = unsafe {
            symcrypt_sys::SymCryptAesBlockCipher
            
        };
        aes_cipher
    }
}
