use core::ffi::c_void;
use std::mem;
use std::ptr;
use std::vec;
use symcrypt_sys;
use crate::errors::SymCryptError;

pub struct GcmState {
    expanded_key: symcrypt_sys::SYMCRYPT_GCM_EXPANDED_KEY,
    state: symcrypt_sys::SYMCRYPT_GCM_STATE,
}

impl GcmState {
    pub fn new(key: &[u8], nonce: &[u8]) -> Result<Box<Self>, SymCryptError> {
        let mut instance = Box::new(GcmState {
            state: symcrypt_sys::SYMCRYPT_GCM_STATE::default(),
            expanded_key: symcrypt_sys::SYMCRYPT_GCM_EXPANDED_KEY::default()
        });
        unsafe {
            expand_key(key, &mut instance.expanded_key)?;
            symcrypt_sys::SymCryptGcmInit(
                &mut instance.state,
                &instance.expanded_key,
                nonce.as_ptr(),
                nonce.len() as symcrypt_sys::SIZE_T,
            );
            Ok(instance)
        }
    }

    pub fn auth(&mut self, auth_data: &[u8]) {
        unsafe {
            symcrypt_sys::SymCryptGcmAuthPart(
                &mut self.state,
                auth_data.as_ptr(),
                auth_data.len() as symcrypt_sys::SIZE_T,
            );
        }
    }

    pub fn encrypt_part(&mut self, data: &[u8]) -> Vec<u8> {
        unsafe {
            let mut dst: Vec<u8> = vec![0u8; data.len()];
            symcrypt_sys::SymCryptGcmEncryptPart(
                &mut self.state,
                data.as_ptr(),
                dst.as_mut_ptr(),
                dst.len() as symcrypt_sys::SIZE_T,
            );
            dst
        }
    }

    pub fn encrypt_final(&mut self, tag: &mut [u8]) {
        unsafe {
            symcrypt_sys::SymCryptGcmEncryptFinal(
                &mut self.state,
                tag.as_mut_ptr(),
                tag.len() as symcrypt_sys::SIZE_T,
            );
        }
    }

    pub fn decrypt_part(&mut self, data: &[u8]) -> Vec<u8> {
        let mut dst: Vec<u8> = vec![0u8; data.len()];
        unsafe {
            symcrypt_sys::SymCryptGcmDecryptPart(
                &mut self.state,
                data.as_ptr(),
                dst.as_mut_ptr(),
                data.len() as symcrypt_sys::SIZE_T,
            );
            dst
        }
    }

    pub fn decrypt_final(&mut self, tag: &[u8]) -> Result<(), SymCryptError> {
        unsafe {
            match symcrypt_sys::SymCryptGcmDecryptFinal(
                &mut self.state,
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
            symcrypt_sys::SymCryptWipe(
                ptr::addr_of_mut!(self.state) as *mut c_void,
                mem::size_of_val(&mut self.state) as symcrypt_sys::SIZE_T,
            );
            symcrypt_sys::SymCryptWipe(
                ptr::addr_of_mut!(self.expanded_key) as *mut c_void,
                mem::size_of_val(&mut self.expanded_key) as symcrypt_sys::SIZE_T,
            );
        }
    }
}

pub fn validate_gcm_parameters(
    block_cipher: symcrypt_sys::PCSYMCRYPT_BLOCKCIPHER,
    nonce: &[u8],
    auth_data: &[u8],
    data: &[u8],
    tag: &[u8],
) -> Result<(), SymCryptError> {
    unsafe {
        match symcrypt_sys::SymCryptGcmValidateParameters(
            block_cipher,
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
    nonce: &[u8],
    auth_data: Option<&[u8]>,
    src: &[u8],
    tag: &mut [u8], // This is an out parameter
) -> Result<Vec<u8>, SymCryptError> {
    unsafe {
        let mut expanded_key = symcrypt_sys::SYMCRYPT_GCM_EXPANDED_KEY::default();
        expand_key(key, &mut expanded_key)?;

        let (auth_data_ptr, auth_data_len) = auth_data.map_or_else(
            || (std::ptr::null(), 0 as symcrypt_sys::SIZE_T),
            |data| (data.as_ptr(), data.len() as symcrypt_sys::SIZE_T),
        );

        let mut dst = vec![0u8; src.len()];

        symcrypt_sys::SymCryptGcmEncrypt(
            &mut expanded_key,
            nonce.as_ptr(),
            nonce.len() as symcrypt_sys::SIZE_T,
            auth_data_ptr,
            auth_data_len as symcrypt_sys::SIZE_T,
            src.as_ptr(),
            dst.as_mut_ptr(),
            src.len() as symcrypt_sys::SIZE_T,
            tag.as_mut_ptr(),
            tag.len() as symcrypt_sys::SIZE_T,
        );
        Ok(dst)
    }
}

pub fn gcm_decrypt(
    key: &[u8],
    nonce: &[u8],
    auth_data: Option<&[u8]>,
    src: &[u8],
    tag: &[u8],
) -> Result<Vec<u8>, SymCryptError> {
    unsafe {
        let mut expanded_key = symcrypt_sys::SYMCRYPT_GCM_EXPANDED_KEY::default();
        expand_key(key, &mut expanded_key)?;

        let (auth_data_ptr, auth_data_len) = auth_data.map_or_else(
            || (std::ptr::null(), 0 as symcrypt_sys::SIZE_T),
            |data| (data.as_ptr(), data.len() as symcrypt_sys::SIZE_T),
        );

        let mut dst = vec![0u8; src.len()];

        match symcrypt_sys::SymCryptGcmDecrypt(
            &mut expanded_key,
            nonce.as_ptr(),
            nonce.len() as symcrypt_sys::SIZE_T,
            auth_data_ptr,
            auth_data_len,
            src.as_ptr(),
            dst.as_mut_ptr(),
            src.len() as symcrypt_sys::SIZE_T,
            tag.as_ptr(),
            tag.len() as symcrypt_sys::SIZE_T,
        ) {
            symcrypt_sys::SYMCRYPT_ERROR_SYMCRYPT_NO_ERROR => Ok(dst),
            err => Err(err.into()),
        }
    }
}

// SymCrypt requires pointer address to stay static through the scope, passing expand_key as an out
// parameter to maintain static pointer address
fn expand_key(key: &[u8], expanded_key: &mut symcrypt_sys::SYMCRYPT_GCM_EXPANDED_KEY) -> Result<(), SymCryptError> {
    unsafe {
        match symcrypt_sys::SymCryptGcmExpandKey(
            expanded_key,
            symcrypt_sys::SymCryptAesBlockCipher,
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

    #[test]
    fn test_stateless_gcm_encrypt_no_ad() {
        let p_key = hex::decode("feffe9928665731c6d6a8f9467308308").unwrap();
        let nonce = hex::decode("cafebabefacedbaddecaf888").unwrap();
        let expected_tag = "4d5c2af327cd64a62cf35abd2ba6fab4";
        let expected_result = "42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091473f5985";
        let pt = hex::decode("d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b391aafd255").unwrap();

        let mut tag: [u8; 16] = [0u8; 16];
        let dst = gcm_encrypt(&p_key, &nonce, None, &pt, &mut tag).unwrap();

        assert_eq!(expected_result, hex::encode(dst));
        assert_eq!(expected_tag, hex::encode(tag));
    }

    #[test]
    fn test_stateless_gcm_encrypt_ad() {
        let p_key = hex::decode("feffe9928665731c6d6a8f9467308308").unwrap();
        let nonce = hex::decode("cafebabefacedbaddecaf888").unwrap();
        let auth_data = hex::decode("feedfacedeadbeeffeedfacedeadbeefabaddad2").unwrap();
        let expected_tag = "5bc94fbc3221a5db94fae95ae7121a47";
        let expected_result = "42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091";
        let pt = hex::decode("d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39").unwrap();
        
        let mut tag = [0u8; 16];
        let dst = gcm_encrypt(&p_key, &nonce, Some(&auth_data), &pt, &mut tag).unwrap();

        assert_eq!(expected_result, hex::encode(dst));
        assert_eq!(expected_tag, hex::encode(tag));
    }

    #[test]
    fn test_stateless_gcm_decrypt_no_ad() {
        let p_key = hex::decode("feffe9928665731c6d6a8f9467308308").unwrap();
        let nonce = hex::decode("cafebabefacedbaddecaf888").unwrap();
        let tag = hex::decode("4d5c2af327cd64a62cf35abd2ba6fab4").unwrap();
        let ct = hex::decode("42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091473f5985").unwrap();
        let expected_result = "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b391aafd255";
        let dst = gcm_decrypt(&p_key, &nonce, None, &ct, &tag).unwrap();

        assert_eq!(expected_result, hex::encode(dst));
    }

    #[test]
    fn test_stateless_gcm_decrypt_ad() {
        let p_key = hex::decode("feffe9928665731c6d6a8f9467308308feffe9928665731c").unwrap();
        let nonce = hex::decode("cafebabefacedbaddecaf888").unwrap();
        let auth_data = hex::decode("feedfacedeadbeeffeedfacedeadbeefabaddad2").unwrap();
        let tag = hex::decode("2519498e80f1478f37ba55bd6d27618c").unwrap();
        let ct = hex::decode("3980ca0b3c00e841eb06fac4872a2757859e1ceaa6efd984628593b40ca1e19c7d773d00c144c525ac619d18c84a3f4718e2448b2fe324d9ccda2710").unwrap();
        let expected_result = "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39";

        let dst = gcm_decrypt(&p_key, &nonce, Some(&auth_data), &ct, &tag).unwrap();

        assert_eq!(expected_result, hex::encode(dst));
    }

    #[test]
    fn test_gcm_encrypt() {
        let p_key = hex::decode("feffe9928665731c6d6a8f9467308308").unwrap();
        let nonce = hex::decode("cafebabefacedbaddecaf888").unwrap();
        let auth_data = hex::decode("feedfacedeadbeeffeedfacedeadbeefabaddad2").unwrap();
        let expected_result = "42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091";
        let pt = hex::decode("d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39").unwrap();

        let expected_tag = "5bc94fbc3221a5db94fae95ae7121a47";
        let mut gcm_state = GcmState::new(&p_key, &nonce).unwrap();
        gcm_state.auth(&auth_data);
        let dst = gcm_state.encrypt_part(&pt);
        assert_eq!(hex::encode(dst), expected_result);
        let mut tag: [u8; 16] = [0u8; 16];

        gcm_state.encrypt_final(&mut tag);
        assert_eq!(hex::encode(tag),expected_tag);
    }

    #[test]
    fn test_gcm_decrypt() { 
        let p_key = hex::decode("feffe9928665731c6d6a8f9467308308").unwrap();
        let nonce = hex::decode("cafebabefacedbaddecaf888").unwrap();
        let auth_data = hex::decode("feedfacedeadbeeffeedfacedeadbeefabaddad2").unwrap();
        let expected_result = "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39";
        let tag = hex::decode("5bc94fbc3221a5db94fae95ae7121a47").unwrap();
        let pt = hex::decode("42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091").unwrap();

        let mut gcm_state = GcmState::new(&p_key, &nonce).unwrap();
        gcm_state.auth(&auth_data);
        let dst = gcm_state.decrypt_part(&pt);
        assert_eq!(hex::encode(dst), expected_result);
        gcm_state.decrypt_final(&tag).unwrap();
    }
    #[test]
    fn test_gcm_decrypt_no_decrypt_part() {
        let p_key = hex::decode("00000000000000000000000000000000").unwrap();
        let nonce = hex::decode("000000000000000000000000").unwrap();
        let auth_data = hex::decode("").unwrap();
        let tag = hex::decode("58e2fccefa7e3061367f1d57a4e7455a").unwrap();

        let mut gcm_state = GcmState::new(&p_key, &nonce).unwrap();
        gcm_state.auth(&auth_data);
        gcm_state.decrypt_final(&tag).unwrap();
    }

    #[test]
    fn test_gcm_encrypt_no_encrypt_part() {
        let p_key = hex::decode("00000000000000000000000000000000").unwrap();
        let nonce = hex::decode("000000000000000000000000").unwrap();
        let auth_data = hex::decode("").unwrap();

        let expected_tag = "58e2fccefa7e3061367f1d57a4e7455a";

        let mut gcm_state = GcmState::new(&p_key, &nonce).unwrap();
        gcm_state.auth(&auth_data);
        let mut tag: [u8; 16] = [0u8; 16];

        gcm_state.encrypt_final(&mut tag);
        assert_eq!(hex::encode(tag),expected_tag);
    } 
    
    #[test]
    fn test_gcm_decrypt_error_message() {
        let p_key = hex::decode("00000000000000000000000000000000").unwrap();
        let nonce = hex::decode("000000000000000000000000").unwrap();
        let auth_data = hex::decode("").unwrap();

        let mut gcm_state = GcmState::new(&p_key, &nonce).unwrap();

        gcm_state.auth(&auth_data);
        let tag: [u8; 16] = [0u8; 16];

        let result = gcm_state.decrypt_final(&tag);
        assert_eq!(result.unwrap_err(), SymCryptError::AuthenticationFailure);
    }

    #[test]
    fn test_validate_parameters() {
        let nonce = hex::decode("cafebabefacedbaddecaf888").unwrap();
        let auth_data = hex::decode("feedfacedeadbeeffeedfacedeadbeefabaddad2").unwrap();
        let expected_tag = hex::decode("5bc94fbc3221a5db94fae95ae7121a47").unwrap();
        let pt = hex::decode("d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39").unwrap();

        unsafe {
            let block_cipher = symcrypt_sys::SymCryptAesBlockCipher;
            validate_gcm_parameters(block_cipher, &nonce, &auth_data, &pt, &expected_tag).unwrap();
        }
    }

    #[test]
    fn test_validate_parameters_fail() {
        let nonce = hex::decode("cafebabefacedbaddecaf888").unwrap();
        let auth_data = hex::decode("feedfacedeadbeeffeedfacedeadbeefabaddad2").unwrap();
        let expected_tag = hex::decode("5bc94fbc3242121a47").unwrap();
        let pt = hex::decode("d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39").unwrap();

        unsafe {
            let block_cipher = symcrypt_sys::SymCryptAesBlockCipher;
            let result = validate_gcm_parameters(block_cipher, &nonce, &auth_data, &pt, &expected_tag);
            assert_eq!(result.unwrap_err(), SymCryptError::WrongTagSize);
        }
    }
}
