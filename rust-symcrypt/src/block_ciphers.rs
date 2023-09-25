//! Friendly rust types for BlockCipherTypes. Currently the only supported BlockCipherType is Aes.

use symcrypt_sys;

pub enum BlockCipherType {
    AesBlock,
}

pub(crate) fn convert_cipher(cipher: BlockCipherType) -> symcrypt_sys::PCSYMCRYPT_BLOCKCIPHER {
    match cipher {
        BlockCipherType::AesBlock => unsafe { symcrypt_sys::SymCryptAesBlockCipher }, // SAFETY: FFI calls
    }
}
