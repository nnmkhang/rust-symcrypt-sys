/* Galois Counter Mode functions. For further documentation please refer to symcrypt.h */

use crate::block_ciphers::*;
use crate::errors::SymCryptError;
use core::ffi::c_void;
use std::mem;
use std::pin::Pin;
use std::ptr;
use std::vec;
use symcrypt_sys;

pub struct GcmState {
    inner: Pin<Box<GcmStateInner>>,
}

struct GcmStateInner {
    state: symcrypt_sys::SYMCRYPT_GCM_STATE,
    expanded_key: symcrypt_sys::SYMCRYPT_GCM_EXPANDED_KEY,
}

/// Using an inner GCM state that is Pin<Box<T>> since the memory address for Self is moved around when returning from GcmState::new()
///
/// SymCrypt expects the address for its structs to stay static through the structs lifetime to guarantee that structs are not memcpy'd as
/// doing so would lead to use-after-free and inconsistent states.
///
/// encrypt_part, decrypt_part take in an allocated buffer as an out parameter for performance reasons. This is for scenarios
/// such as encrypting over a stream of data; allocating and copying data from a return will be costly performance wise.
///
/// Since auth_part, encrypt_part and decrypt_part may be called multiple times, you must call encrypt_final/decrypt_final at the end to ensure
/// that the encryption/decryption has completed successfully.
///
/// The only accepted Cipher for GCM is AesBlock.
impl GcmState {
    pub fn new(
        key: &[u8],
        nonce: &[u8; 12], // GCM nonce length must be 12 bytes
        cipher: BlockCipherType,
    ) -> Result<Self, SymCryptError> {
        let mut instance = GcmState {
            inner: Box::pin(GcmStateInner {
                state: symcrypt_sys::SYMCRYPT_GCM_STATE::default(),
                expanded_key: symcrypt_sys::SYMCRYPT_GCM_EXPANDED_KEY::default(),
            }),
        };

        gcm_expand_key(
            key,
            &mut instance.inner.expanded_key,
            convert_cipher(cipher),
        )?;
        unsafe {
            // SAFETY: FFI calls
            symcrypt_sys::SymCryptGcmInit(
                &mut instance.inner.state,
                &instance.inner.expanded_key,
                nonce.as_ptr(),
                nonce.len() as symcrypt_sys::SIZE_T,
            );
            Ok(instance)
        }
    }

    // Can be called multiple times
    pub fn auth_part(&mut self, auth_data: &[u8]) {
        unsafe {
            // SAFETY: FFI calls
            symcrypt_sys::SymCryptGcmAuthPart(
                &mut self.inner.state,
                auth_data.as_ptr(),
                auth_data.len() as symcrypt_sys::SIZE_T,
            );
        }
    }

    // Can be called multiple times
    // Takes in a buffer as an out parameter for performance reasons
    pub fn encrypt_part(&mut self, plain_text: &[u8], cipher_text_buffer: &mut [u8]) {
        assert_eq!(
            plain_text.len(),
            cipher_text_buffer.len(),
            "plain_text and cipher_text_buffer must be the same length"
        );
        unsafe {
            // SAFETY: FFI calls
            symcrypt_sys::SymCryptGcmEncryptPart(
                &mut self.inner.state,
                plain_text.as_ptr(),
                cipher_text_buffer.as_mut_ptr(),
                cipher_text_buffer.len() as symcrypt_sys::SIZE_T,
            );
        }
    }

    pub fn encrypt_final(&mut self, tag: &mut [u8]) {
        unsafe {
            // SAFETY: FFI calls
            symcrypt_sys::SymCryptGcmEncryptFinal(
                &mut self.inner.state,
                tag.as_mut_ptr(),
                tag.len() as symcrypt_sys::SIZE_T,
            );
        }
    }

    // Can be called multiple times
    // Takes in a buffer as an out parameter for performance reasons
    pub fn decrypt_part(&mut self, cipher_text: &[u8], plain_text_buffer: &mut [u8]) {
        assert_eq!(
            cipher_text.len(),
            plain_text_buffer.len(),
            "cipher_text and plain_text_buffer must be the same length"
        );
        unsafe {
            // SAFETY: FFI calls
            symcrypt_sys::SymCryptGcmDecryptPart(
                &mut self.inner.state,
                cipher_text.as_ptr(),
                plain_text_buffer.as_mut_ptr(),
                plain_text_buffer.len() as symcrypt_sys::SIZE_T,
            );
        }
    }

    pub fn decrypt_final(&mut self, tag: &[u8]) -> Result<(), SymCryptError> {
        unsafe {
            // SAFETY: FFI calls
            match symcrypt_sys::SymCryptGcmDecryptFinal(
                &mut self.inner.state,
                tag.as_ptr(),
                tag.len() as symcrypt_sys::SIZE_T,
            ) {
                symcrypt_sys::SYMCRYPT_ERROR_SYMCRYPT_NO_ERROR => Ok(()),
                err => Err(err.into()),
            }
        }
    }
}

impl Drop for GcmState {
    fn drop(&mut self) {
        unsafe {
            // SAFETY: FFI calls
            symcrypt_sys::SymCryptWipe(
                ptr::addr_of_mut!(self.inner.state) as *mut c_void,
                mem::size_of_val(&mut self.inner.state) as symcrypt_sys::SIZE_T,
            );
            symcrypt_sys::SymCryptWipe(
                ptr::addr_of_mut!(self.inner.expanded_key) as *mut c_void,
                mem::size_of_val(&mut self.inner.expanded_key) as symcrypt_sys::SIZE_T,
            );
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

pub fn gcm_encrypt(
    key: &[u8],
    nonce: &[u8; 12],
    auth_data: Option<&[u8]>,
    plain_text: &[u8],
    tag_length: usize,
    cipher: BlockCipherType,
) -> Result<(Vec<u8>, Vec<u8>), SymCryptError> {
    let mut expanded_key = symcrypt_sys::SYMCRYPT_GCM_EXPANDED_KEY::default();
    gcm_expand_key(key, &mut expanded_key, convert_cipher(cipher))?;

    let (auth_data_ptr, auth_data_len) = auth_data.map_or_else(
        || (std::ptr::null(), 0 as symcrypt_sys::SIZE_T),
        |data| (data.as_ptr(), data.len() as symcrypt_sys::SIZE_T),
    );

    let mut cipher_text = vec![0u8; plain_text.len()];
    let mut tag = vec![0u8; tag_length];
    unsafe {
        // SAFETY: FFI calls
        symcrypt_sys::SymCryptGcmEncrypt(
            &mut expanded_key,
            nonce.as_ptr(),
            nonce.len() as symcrypt_sys::SIZE_T,
            auth_data_ptr,
            auth_data_len as symcrypt_sys::SIZE_T,
            plain_text.as_ptr(),
            cipher_text.as_mut_ptr(),
            plain_text.len() as symcrypt_sys::SIZE_T,
            tag.as_mut_ptr(),
            tag.len() as symcrypt_sys::SIZE_T,
        );
        Ok((cipher_text, tag))
    }
}

pub fn gcm_decrypt(
    key: &[u8],
    nonce: &[u8; 12],
    auth_data: Option<&[u8]>,
    cipher_text: &[u8],
    tag: &[u8],
    cipher: BlockCipherType,
) -> Result<Vec<u8>, SymCryptError> {
    let mut expanded_key = symcrypt_sys::SYMCRYPT_GCM_EXPANDED_KEY::default();
    gcm_expand_key(key, &mut expanded_key, convert_cipher(cipher))?;

    let (auth_data_ptr, auth_data_len) = auth_data.map_or_else(
        || (std::ptr::null(), 0 as symcrypt_sys::SIZE_T),
        |data| (data.as_ptr(), data.len() as symcrypt_sys::SIZE_T),
    );

    let mut plain_text = vec![0u8; cipher_text.len()];
    unsafe {
        // SAFETY: FFI calls
        match symcrypt_sys::SymCryptGcmDecrypt(
            &mut expanded_key,
            nonce.as_ptr(),
            nonce.len() as symcrypt_sys::SIZE_T,
            auth_data_ptr,
            auth_data_len,
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

#[cfg(test)]
mod test {
    use super::*;
    use crate::block_ciphers::BlockCipherType;
    #[test]
    fn test_stateless_gcm_encrypt_no_ad() {
        let p_key = hex::decode("feffe9928665731c6d6a8f9467308308").unwrap();
        let mut nonce_array = [0u8; 12];
        hex::decode_to_slice("cafebabefacedbaddecaf888", &mut nonce_array).unwrap();
        let expected_tag = "4d5c2af327cd64a62cf35abd2ba6fab4";
        let expected_result = "42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091473f5985";
        let pt = hex::decode("d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b391aafd255").unwrap();

        let cipher = BlockCipherType::AesBlock;
        let (dst, tag) = gcm_encrypt(&p_key, &nonce_array, None, &pt, 16, cipher).unwrap();

        assert_eq!(expected_result, hex::encode(dst));
        assert_eq!(expected_tag, hex::encode(tag));
    }

    #[test]
    fn test_stateless_gcm_encrypt_ad() {
        let p_key = hex::decode("feffe9928665731c6d6a8f9467308308").unwrap();
        let mut nonce_array = [0u8; 12];
        hex::decode_to_slice("cafebabefacedbaddecaf888", &mut nonce_array).unwrap();
        let auth_data = hex::decode("feedfacedeadbeeffeedfacedeadbeefabaddad2").unwrap();
        let expected_tag = "5bc94fbc3221a5db94fae95ae7121a47";
        let expected_result = "42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091";
        let pt = hex::decode("d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39").unwrap();

        let cipher = BlockCipherType::AesBlock;
        let (dst, tag) =
            gcm_encrypt(&p_key, &nonce_array, Some(&auth_data), &pt, 16, cipher).unwrap();

        assert_eq!(expected_result, hex::encode(dst));
        assert_eq!(expected_tag, hex::encode(tag));
    }

    #[test]
    fn test_stateless_gcm_decrypt_no_ad() {
        let p_key = hex::decode("feffe9928665731c6d6a8f9467308308").unwrap();
        let mut nonce_array = [0u8; 12];
        hex::decode_to_slice("cafebabefacedbaddecaf888", &mut nonce_array).unwrap();
        let tag = hex::decode("4d5c2af327cd64a62cf35abd2ba6fab4").unwrap();
        let ct = hex::decode("42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091473f5985").unwrap();
        let expected_result = "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b391aafd255";
        let cipher = BlockCipherType::AesBlock;

        let dst = gcm_decrypt(&p_key, &nonce_array, None, &ct, &tag, cipher).unwrap();

        assert_eq!(expected_result, hex::encode(dst));
    }

    #[test]
    fn test_stateless_gcm_decrypt_ad() {
        let p_key = hex::decode("feffe9928665731c6d6a8f9467308308feffe9928665731c").unwrap();
        let mut nonce_array = [0u8; 12];
        hex::decode_to_slice("cafebabefacedbaddecaf888", &mut nonce_array).unwrap();
        let auth_data = hex::decode("feedfacedeadbeeffeedfacedeadbeefabaddad2").unwrap();
        let tag = hex::decode("2519498e80f1478f37ba55bd6d27618c").unwrap();
        let ct = hex::decode("3980ca0b3c00e841eb06fac4872a2757859e1ceaa6efd984628593b40ca1e19c7d773d00c144c525ac619d18c84a3f4718e2448b2fe324d9ccda2710").unwrap();
        let expected_result = "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39";
        let cipher = BlockCipherType::AesBlock;

        let dst = gcm_decrypt(&p_key, &nonce_array, Some(&auth_data), &ct, &tag, cipher).unwrap();

        assert_eq!(expected_result, hex::encode(dst));
    }

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

        let mut gcm_state = GcmState::new(&p_key, &nonce_array, cipher).unwrap();
        gcm_state.auth_part(&auth_data);
        gcm_state.encrypt_part(&pt, &mut ct);
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
        let mut ct = vec![0; pt.len()];

        let expected_tag = "5bc94fbc3221a5db94fae95ae7121a47";
        let cipher = BlockCipherType::AesBlock;

        let mut gcm_state = GcmState::new(&p_key, &nonce_array, cipher).unwrap();
        gcm_state.auth_part(&auth_data);
        gcm_state.encrypt_part(&pt, &mut ct);
        assert_eq!(hex::encode(ct), expected_result);
        let mut tag: [u8; 16] = [0u8; 16];

        gcm_state.encrypt_final(&mut tag);
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
        let mut pt = vec![0; ct.len()];

        let mut gcm_state = GcmState::new(&p_key, &nonce_array, cipher).unwrap();
        gcm_state.auth_part(&auth_data);
        gcm_state.decrypt_part(&ct, &mut pt);
        assert_eq!(hex::encode(pt), expected_result);
        gcm_state.decrypt_final(&tag).unwrap();
    }

    #[test]
    fn test_gcm_decrypt_no_decrypt_part() {
        let p_key = hex::decode("00000000000000000000000000000000").unwrap();
        let mut nonce_array = [0u8; 12];
        hex::decode_to_slice("000000000000000000000000", &mut nonce_array).unwrap();
        let auth_data = hex::decode("").unwrap();
        let tag = hex::decode("58e2fccefa7e3061367f1d57a4e7455a").unwrap();
        let cipher = BlockCipherType::AesBlock;

        let mut gcm_state = GcmState::new(&p_key, &nonce_array, cipher).unwrap();
        gcm_state.auth_part(&auth_data);
        gcm_state.decrypt_final(&tag).unwrap();
    }

    #[test]
    fn test_gcm_encrypt_no_encrypt_part() {
        let p_key = hex::decode("00000000000000000000000000000000").unwrap();
        let mut nonce_array = [0u8; 12];
        hex::decode_to_slice("000000000000000000000000", &mut nonce_array).unwrap();
        let auth_data = hex::decode("").unwrap();

        let expected_tag = "58e2fccefa7e3061367f1d57a4e7455a";
        let cipher = BlockCipherType::AesBlock;

        let mut gcm_state = GcmState::new(&p_key, &nonce_array, cipher).unwrap();
        gcm_state.auth_part(&auth_data);
        let mut tag: [u8; 16] = [0u8; 16];

        gcm_state.encrypt_final(&mut tag);
        assert_eq!(hex::encode(tag), expected_tag);
    }

    #[test]
    fn test_gcm_decrypt_error_message() {
        let p_key = hex::decode("00000000000000000000000000000000").unwrap();
        let mut nonce_array = [0u8; 12];
        hex::decode_to_slice("000000000000000000000000", &mut nonce_array).unwrap();
        let auth_data = hex::decode("").unwrap();
        let cipher = BlockCipherType::AesBlock;

        let mut gcm_state = GcmState::new(&p_key, &nonce_array, cipher).unwrap();

        gcm_state.auth_part(&auth_data);
        let tag: [u8; 16] = [0u8; 16];

        let result = gcm_state.decrypt_final(&tag);
        assert_eq!(result.unwrap_err(), SymCryptError::AuthenticationFailure);
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
