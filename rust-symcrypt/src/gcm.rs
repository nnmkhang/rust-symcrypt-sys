use core::ffi::c_void;
use std::mem;
use std::ptr;
use std::vec;
use symcrypt_sys;

pub struct GcmState {
    state: symcrypt_sys::SYMCRYPT_GCM_STATE,
    expanded_key: symcrypt_sys::SYMCRYPT_GCM_EXPANDED_KEY
}
impl GcmState {
    // does gcm ONLY use aesBlockCipher? Should I account for other block ciphers being used?
    // If  I wrap in a return, i get STATUS_STACK_BUFFER_OVERRUN Error
    pub fn new(key: &[u8], nonce: &[u8]) -> Self {
        let mut instance = GcmState {
            state: symcrypt_sys::SYMCRYPT_GCM_STATE::default(),
            expanded_key: symcrypt_sys::SYMCRYPT_GCM_EXPANDED_KEY::default()
        };
        unsafe {
            //let mut expanded_key = expand_key(key)?;

            match symcrypt_sys::SymCryptGcmExpandKey(
                &mut instance.expanded_key,
                symcrypt_sys::SymCryptAesBlockCipher,
                key.as_ptr(),
                key.len() as symcrypt_sys::SIZE_T,
            ) {
                symcrypt_sys::SYMCRYPT_ERROR_SYMCRYPT_NO_ERROR => {}
                err => {
                    //return Err(err)
                    panic!()
                }
            }

            // pub struct _SYMCRYPT_GCM_STATE {
            //     pub pKey: PCSYMCRYPT_GCM_EXPANDED_KEY,
            //     pub cbData: UINT64,
            //     pub cbAuthData: UINT64,
            //     pub bytesInMacBlock: SIZE_T,
            //     pub ghashState: SYMCRYPT_GF128_ELEMENT,
            //     pub counterBlock: [BYTE; 16usize],
            //     pub macBlock: [BYTE; 16usize],
            //     pub keystreamBlock: [BYTE; 16usize],
            //     pub magic: SIZE_T,
            // }
            symcrypt_sys::SymCryptGcmInit(
                &mut instance.state,
                &instance.expanded_key,
                nonce.as_ptr(),
                nonce.len() as symcrypt_sys::SIZE_T,
            );
            println!("Hi");
            
            // Ok(instance)
            println!("expanded key");
            println!("{:p}", &instance.expanded_key);
            println!("instance:");
            println!("{:p}", &instance);

            instance
        }
    }

    pub fn auth(&mut self, auth_data: &[u8]) {
        unsafe {

            println!("instance auth:");
            println!("{:p}", &self.state);
            symcrypt_sys::SymCryptGcmAuthPart(
                &mut self.state,
                auth_data.as_ptr(),
                auth_data.len() as symcrypt_sys::SIZE_T,
            );
        }
    }

    pub fn encrypt_part(&mut self, data: &[u8]) -> Vec<u8> {
        unsafe {
            let mut dst: Vec<u8> = vec![0u8; data.len()]; // could it be that vec has extra stuff that is causing the error here?
            println!("instance encrypt_part:");
            println!("{:p}", &self.state);
            symcrypt_sys::SymCryptGcmEncryptPart(
                &mut self.state,
                data.as_ptr(), // here is where the memory goes kaput for pblockcipher
                dst.as_mut_ptr(),
                dst.len() as symcrypt_sys::SIZE_T,
            );
            dst
        }
    }

    pub fn encrypt_final(&mut self) -> Vec<u8> {
        let mut tag = vec![0u8; 16]; //cbTag: size of tag. cbTag must be one of {4, 6, 8, 10, 12, 14, 16}.
        unsafe {
            symcrypt_sys::SymCryptGcmEncryptFinal(
                &mut self.state,
                tag.as_mut_ptr(),
                tag.len() as symcrypt_sys::SIZE_T,
            );
        }
        tag
    }

    pub fn decrypt_part(&mut self, data: &[u8]) -> Vec<u8> {
        // could take decrypt over packets or multiple buffers,
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

    pub fn decrypt_final(&mut self) -> Result<Vec<u8>, symcrypt_sys::SYMCRYPT_ERROR> {
        //tag can be validated,can run decrypt_final without decrypt part , can fail
        let mut tag = vec![0u8; 16]; //figure out actual size
        unsafe {
            match symcrypt_sys::SymCryptGcmDecryptFinal(
                &mut self.state,
                tag.as_mut_ptr(),
                tag.len() as symcrypt_sys::SIZE_T,
            ) {
                symcrypt_sys::SYMCRYPT_ERROR_SYMCRYPT_NO_ERROR => Ok(tag),
                err => Err(err),
            }
        }
    }
}

impl Drop for GcmState {
    fn drop(&mut self) {
        // do i need to clear the expanded key as well?
        unsafe {
            symcrypt_sys::SymCryptWipe(
                ptr::addr_of_mut!(self.state) as *mut c_void,
                mem::size_of_val(&mut self.state) as symcrypt_sys::SIZE_T,
            )
        }
    }
}
// SymCryptGcmValidateParameters can expose this instead of calling since you'd probably know
pub fn validate_gcm_parameters(
    block_cipher: symcrypt_sys::PCSYMCRYPT_BLOCKCIPHER,
    len_nonce: usize,
    len_ad: symcrypt_sys::UINT64,
    len_data: usize,
    len_tag: usize,
) -> Result<(), symcrypt_sys::SYMCRYPT_ERROR> {
    unsafe {
        match symcrypt_sys::SymCryptGcmValidateParameters(
            block_cipher,
            len_nonce as symcrypt_sys::SIZE_T,
            len_ad as symcrypt_sys::UINT64,
            len_data as symcrypt_sys::SIZE_T,
            len_tag as symcrypt_sys::SIZE_T,
        ) {
            symcrypt_sys::SYMCRYPT_ERROR_SYMCRYPT_NO_ERROR => Ok(()),
            err => Err(err),
        }
    }
}

pub fn gcm_encrypt(
    key: &[u8],
    nonce: &[u8],
    auth_data: Option<&[u8]>,
    src: &[u8],
) -> Result<(Vec<u8>, Vec<u8>), symcrypt_sys::SYMCRYPT_ERROR> {
    unsafe {
        let mut expanded_key = expand_key(key)?; // When i run this code, it errors out with : STATUS_STACK_BUFFER_OVERRUN

        println!("inside gcm_encrypt");
        println!("{:p}", &expanded_key);

        // the "let mut " part is creating a copy. we dont want a copy we want t he eXACT pointer address. 




        // let mut expanded_key = symcrypt_sys::SYMCRYPT_GCM_EXPANDED_KEY::default();
        // match symcrypt_sys::SymCryptGcmExpandKey(
        //     &mut expanded_key,
        //     symcrypt_sys::SymCryptAesBlockCipher,
        //     key.as_ptr(),
        //     key.len() as symcrypt_sys::SIZE_T,
        // ) {
        //     symcrypt_sys::SYMCRYPT_ERROR_SYMCRYPT_NO_ERROR => {}
        //     err => return Err(err),
        // }


        // pub struct _SYMCRYPT_GCM_EXPANDED_KEY {
        //     pub ghashKey: SYMCRYPT_GHASH_EXPANDED_KEY,
        //     pub pBlockCipher: PCSYMCRYPT_BLOCKCIPHER,
        //     pub __bindgen_padding_0: u64,
        //     pub blockcipherKey: SYMCRYPT_GCM_SUPPORTED_BLOCKCIPHER_KEYS,
        //     pub cbKey: SIZE_T,
        //     pub abKey: [BYTE; 32usize],
        //     pub magic: SIZE_T,
        // }

        let (auth_data_ptr, auth_data_len) = auth_data.map_or_else(
            || (std::ptr::null(), 0 as symcrypt_sys::SIZE_T),
            |data| (data.as_ptr(), data.len() as symcrypt_sys::SIZE_T),
        );

        let mut dst = vec![0u8; src.len()]; // this works. encrypt_part does not work though??
        let mut tag = vec![0u8; 16]; // figure this out

        symcrypt_sys::SymCryptGcmEncrypt(
            &mut *expanded_key,
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
        Ok((dst, tag))
    }
}

pub fn gcm_decrypt(
    key: &[u8],
    nonce: &[u8],
    auth_data: Option<&[u8]>,
    src: &[u8],
    tag: &[u8],
) -> Result<Vec<u8>, symcrypt_sys::SYMCRYPT_ERROR> {
    unsafe {
        // let mut expanded_key = expand_key(key)?;
        // magic: 63826318631
        // 610444779239  breaking  magic 

        let mut expanded_key = symcrypt_sys::SYMCRYPT_GCM_EXPANDED_KEY::default();
        println!("{:p}", &expanded_key);

        match symcrypt_sys::SymCryptGcmExpandKey(
            &mut expanded_key,
            symcrypt_sys::SymCryptAesBlockCipher,
            key.as_ptr(),
            key.len() as symcrypt_sys::SIZE_T,
        ) {
            symcrypt_sys::SYMCRYPT_ERROR_SYMCRYPT_NO_ERROR => {}
            err => return Err(err),
        }
        println!("{:p}", &expanded_key);

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
            err => Err(err),
        }
    }
}

fn expand_key(
    key: &[u8],
) -> Result<Box<symcrypt_sys::SYMCRYPT_GCM_EXPANDED_KEY>, symcrypt_sys::SYMCRYPT_ERROR> { // can we force the memory position to be the same?
    let mut expanded_key = Box::new(symcrypt_sys::SYMCRYPT_GCM_EXPANDED_KEY::default()); // alternative is to take the variable as an out parameter and assign the value there in the scope where you need it 
    // whats happening now is that expand_key is moving the pointer after when it returns 
    // could also allocate this on the stack 
    
    unsafe {
        //610444779239
        match symcrypt_sys::SymCryptGcmExpandKey(
            &mut *expanded_key,
            symcrypt_sys::SymCryptAesBlockCipher,
            key.as_ptr(),
            key.len() as symcrypt_sys::SIZE_T,
        ) {
            symcrypt_sys::SYMCRYPT_ERROR_SYMCRYPT_NO_ERROR => 
            {
                println!("{:p}", &expanded_key);
                return Ok(expanded_key)
            }
            err => Err(err),
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

        let (dst, tag) = gcm_encrypt(&p_key, &nonce, None, &pt).unwrap();

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

        let (dst, tag) = gcm_encrypt(&p_key, &nonce, Some(&auth_data), &pt).unwrap();

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
        let expected_result = "42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091473f5985";

        let pt = hex::decode("d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b391aafd255").unwrap();

        let mut gcm_state = GcmState::new(&p_key, &nonce);
        gcm_state.auth(&auth_data);
        let dst = gcm_state.encrypt_part(&pt);
        assert_eq!(hex::encode(dst), expected_result);
    }

    #[test]
    fn test_gcm_decrypt() {}
}
