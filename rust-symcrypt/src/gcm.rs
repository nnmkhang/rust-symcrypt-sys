//! Galois Counter Mode functions. For further documentation please refer to symcrypt.h

use crate::block_ciphers::*;
use crate::errors::SymCryptError;
use std::pin::Pin;
use std::vec;
use symcrypt_sys;

// /// Using an inner GCM state that is Pin<Box<T>> since the memory address for Self is moved around when returning from GcmExpandedKey::new()
// ///
// /// SymCrypt expects the address for its structs to stay static through the structs lifetime to guarantee that structs are not memcpy'd as
// /// doing so would lead to use-after-free and inconsistent states.
// ///
// /// encrypt_part, decrypt_part take in an allocated buffer as an out parameter for performance reasons. This is for scenarios
// /// such as encrypting over a stream of data; allocating and copying data from a return will be costly performance wise.
// ///
// /// Since auth_part, encrypt_part and decrypt_part may be called multiple times, you must call encrypt_final/decrypt_final at the end to ensure
// /// that the encryption/decryption has completed successfully.
// ///
// /// The only accepted Cipher for GCM is AesBlock.


// SymCrypt requires pointer address to stay static through the scope, passing expand_key as an out
// parameter to maintain static pointer address
fn gcm_expand_key(
    key: &[u8],
    expanded_key: &mut symcrypt_sys::SYMCRYPT_GCM_EXPANDED_KEY,
    cipher: *const symcrypt_sys::SYMCRYPT_BLOCKCIPHER,
) -> Result<(), SymCryptError> {
    unsafe {
        // SAFETY: FFI calls
        match symcrypt_sys::SymCryptGcmExpandKey(
            expanded_key,
            cipher,
            key.as_ptr(),
            key.len() as symcrypt_sys::SIZE_T,
        ) {
            symcrypt_sys::SYMCRYPT_ERROR_SYMCRYPT_NO_ERROR => Ok(()),
            err => Err(err.into()),
        }
    }
}
// struct GcmExpandedKeyInner{key: symcrypt_sys::SYMCRYPT_GCM_EXPANDED_KEY}
pub struct GcmExpandedKey(Pin<Box<symcrypt_sys::SYMCRYPT_GCM_EXPANDED_KEY>>);

impl GcmExpandedKey {
    pub fn new(key: &[u8], cipher: BlockCipherType) -> Result<Self, SymCryptError> {
        let mut expanded_key = Box::pin(symcrypt_sys::SYMCRYPT_GCM_EXPANDED_KEY::default()); // boxing here so that the memory is not moved
        gcm_expand_key(key, &mut expanded_key, convert_cipher(cipher))?;
        let gcm_expanded_key = GcmExpandedKey(expanded_key);
        Ok(gcm_expanded_key)
    }

    pub fn encrypt(
        &mut self,
        nonce: &[u8; 12],
        auth_data: &[u8],
        plain_text: &[u8],
        tag_length: usize,
    ) -> Result<(Vec<u8>, Vec<u8>), SymCryptError> {
        let mut cipher_text = vec![0u8; plain_text.len()];
        let mut tag = vec![0u8; tag_length];
        unsafe {
            // SAFETY: FFI calls
            symcrypt_sys::SymCryptGcmEncrypt(
                &mut *self.0,
                nonce.as_ptr(),
                nonce.len() as symcrypt_sys::SIZE_T,
                auth_data.as_ptr(),
                auth_data.len() as symcrypt_sys::SIZE_T,
                plain_text.as_ptr(),
                cipher_text.as_mut_ptr(),
                plain_text.len() as symcrypt_sys::SIZE_T,
                tag.as_mut_ptr(),
                tag.len() as symcrypt_sys::SIZE_T,
            );
            Ok((cipher_text, tag))
        }
    }

    pub fn decrypt(
        &mut self,
        nonce: &[u8; 12],
        auth_data: &[u8],
        cipher_text: &[u8],
        tag: &[u8],
    ) -> Result<Vec<u8>, SymCryptError> {
        let mut plain_text = vec![0u8; cipher_text.len()];
        unsafe {
            // SAFETY: FFI calls
            match symcrypt_sys::SymCryptGcmDecrypt(
                &mut *self.0,
                nonce.as_ptr(),
                nonce.len() as symcrypt_sys::SIZE_T,
                auth_data.as_ptr(),
                auth_data.len() as symcrypt_sys::SIZE_T,
                cipher_text.as_ptr(),
                plain_text.as_mut_ptr(),
                cipher_text.len() as symcrypt_sys::SIZE_T,
                tag.as_ptr(),
                tag.len() as symcrypt_sys::SIZE_T,
            ) {
                symcrypt_sys::SYMCRYPT_ERROR_SYMCRYPT_NO_ERROR => Ok(plain_text),
                err => Err(err.into()),
            }
        }
    }
}

pub fn validate_gcm_parameters(
    cipher: BlockCipherType,
    nonce: &[u8; 12], // GCM nonce length must be 12 bytes
    auth_data: &[u8],
    data: &[u8],
    tag: &[u8],
) -> Result<(), SymCryptError> {
    unsafe {
        // SAFETY: FFI calls
        match symcrypt_sys::SymCryptGcmValidateParameters(
            convert_cipher(cipher),
            nonce.len() as symcrypt_sys::SIZE_T,
            auth_data.len() as symcrypt_sys::UINT64,
            data.len() as symcrypt_sys::SIZE_T,
            tag.len() as symcrypt_sys::SIZE_T,
        ) {
            symcrypt_sys::SYMCRYPT_ERROR_SYMCRYPT_NO_ERROR => Ok(()),
            err => Err(err.into()),
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::block_ciphers::BlockCipherType;

    #[test]
    #[should_panic]
    fn test_gcm_encrypt_panics_on_length_mismatch() {
        let p_key = hex::decode("feffe9928665731c6d6a8f9467308308").unwrap();
        let mut nonce_array = [0u8; 12];
        hex::decode_to_slice("cafebabefacedbaddecaf888", &mut nonce_array).unwrap();
        let auth_data = hex::decode("feedfacedeadbeeffeedfacedeadbeefabaddad2").unwrap();
        let expected_result = "42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091";
        let pt = hex::decode("d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39").unwrap();
        let mut ct = vec![0; 6];

        let cipher = BlockCipherType::AesBlock;

        let mut gcm_state = GcmExpandedKey::new(&p_key, cipher).unwrap();
        let (ct, tag) = gcm_state.encrypt(&nonce_array, &auth_data, &pt, 16).unwrap();
        assert_eq!(hex::encode(ct), expected_result);
    }

    #[test]
    fn test_gcm_encrypt() {
        let p_key = hex::decode("feffe9928665731c6d6a8f9467308308").unwrap();
        let mut nonce_array = [0u8; 12];
        hex::decode_to_slice("cafebabefacedbaddecaf888", &mut nonce_array).unwrap();
        let auth_data = hex::decode("feedfacedeadbeeffeedfacedeadbeefabaddad2").unwrap();
        let expected_result = "42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091";
        let pt = hex::decode("d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39").unwrap();

        let expected_tag = "5bc94fbc3221a5db94fae95ae7121a47";
        let cipher = BlockCipherType::AesBlock;

        let mut gcm_state = GcmExpandedKey::new(&p_key, cipher).unwrap();
        let (ct, tag) = gcm_state.encrypt(&nonce_array, &auth_data, &pt, 16).unwrap();

        assert_eq!(hex::encode(ct), expected_result);
        assert_eq!(hex::encode(tag), expected_tag);
    }

    #[test]
    fn test_gcm_decrypt() {
        let p_key = hex::decode("feffe9928665731c6d6a8f9467308308").unwrap();
        let mut nonce_array = [0u8; 12];
        hex::decode_to_slice("cafebabefacedbaddecaf888", &mut nonce_array).unwrap();
        let auth_data = hex::decode("feedfacedeadbeeffeedfacedeadbeefabaddad2").unwrap();
        let expected_result = "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39";
        let tag = hex::decode("5bc94fbc3221a5db94fae95ae7121a47").unwrap();
        let ct = hex::decode("42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091").unwrap();
        let cipher = BlockCipherType::AesBlock;

        let mut gcm_state = GcmExpandedKey::new(&p_key,cipher).unwrap();
        let (pt) = gcm_state.decrypt(&nonce_array, &auth_data, &ct, &tag).unwrap();
        assert_eq!(hex::encode(pt), expected_result);
    }

    #[test]
    fn test_validate_parameters() {
        let mut nonce_array = [0u8; 12];
        hex::decode_to_slice("cafebabefacedbaddecaf888", &mut nonce_array).unwrap();
        let auth_data = hex::decode("feedfacedeadbeeffeedfacedeadbeefabaddad2").unwrap();
        let expected_tag = hex::decode("5bc94fbc3221a5db94fae95ae7121a47").unwrap();
        let pt = hex::decode("d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39").unwrap();
        let cipher = BlockCipherType::AesBlock;

        validate_gcm_parameters(cipher, &nonce_array, &auth_data, &pt, &expected_tag).unwrap();
    }

    #[test]
    fn test_validate_parameters_fail() {
        let mut nonce_array = [0u8; 12];
        hex::decode_to_slice("cafebabefacedbaddecaf888", &mut nonce_array).unwrap();
        let auth_data = hex::decode("feedfacedeadbeeffeedfacedeadbeefabaddad2").unwrap();
        let expected_tag = hex::decode("5bc94fbc3242121a47").unwrap();
        let pt = hex::decode("d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39").unwrap();
        let cipher = BlockCipherType::AesBlock;

        let result = validate_gcm_parameters(cipher, &nonce_array, &auth_data, &pt, &expected_tag);
        assert_eq!(result.unwrap_err(), SymCryptError::WrongTagSize);
    }
}
