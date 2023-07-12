use core::ffi::c_void;
use std::mem;
use std::ptr;
use symcrypt_sys;



// The following must be called to get the PCSYMCRYPT_GCM_EXPANDED_KEY:
// SymCryptGcmExpandKey(). You will pass SymCryptAesBlockCipher for the PCSYMCRYPT_BLOCKCIPHER. Note this can fail with a SYMCRYPT_ERROR.

// There are two stateless APIs: SymCryptGcmEncrypt() and SymCryptGcmDecrypt(). In addition to these parameters you will also need to be passed the pbKey for the above.
// You will first call SymCryptGcmValidateParameters() to verify the length of the input slice parameters.


pub fn gcm_encrypt() {
    // pExpandedKey: PCSYMCRYPT_GCM_EXPANDED_KEY,
    // pbNonce: PCBYTE,
    // cbNonce: SIZE_T,
    // pbAuthData: PCBYTE,
    // cbAuthData: SIZE_T,
    // pbSrc: PCBYTE,
    // pbDst: PBYTE,
    // cbData: SIZE_T,
    // pbTag: PBYTE,
    // cbTag: SIZE_T,
}

pub fn gcm_decrypt(p_key: &[u8]) { 

    unsafe {
        let mut expanded_key = symcrypt_sys::SYMCRYPT_GCM_EXPANDED_KEY::default();
        let mut p_block = symcrypt_sys::SYMCRYPT_BLOCKCIPHER::default();

        symcrypt_sys::SymCryptGcmExpandKey(
            &mut expanded_key, 
            &mut p_block, 
            p_key.as_ptr(), 
            p_key.len() as symcrypt_sys::SIZE_T 
        );

        symcrypt_sys::SymCryptGcmEncrypt(
            expanded_key, 
            None,
            None, 
            pbAuthData,
            cbAuthData,
            pbSrc,
            pbDst,
            cbData,
            pbTag,  
            cbTag
            );
    }
}


//  Encrypt a buffer using the block cipher in GCM mode.
//      - pExpandedKey points to the expanded key for GCM.
//      - pbNonce: Pointer to the nonce for this encryption. For a single key, each nonce
//          value may be used at most once to encrypt data. Re-using nonce values leads
//          to catastrophic loss of security. Only 12-byte nonces are supported,
//          per the SP800-38D section 5.2.1.1 recommendation.
//      - cbNonce: number of bytes in the nonce, must be 12.
//      - pbAuthData: pointer to the associated authentication data. This data is not encrypted
//          but it is included in the authentication. Use NULL if not used.
//      - cbAuthData: # bytes of associated authentication data. (0 if not used)
//      - pbSrc: plaintext input
//      - pbDst: ciphertext output. The ciphertext buffer may be identical to the plaintext
//          buffer, or non-overlapping. The ciphertext is also cbData bytes long.
//      - cbData: # bytes of plaintext input. The maximum length is 2^{36} - 32 bytes.
//      - pbTag: buffer that will receive the authentication tag.
//      - cbTag: size of tag. cbTag must be one of {12, 13, 14, 15, 16} per SP800-38D
//          section 5.2.1.2. The optional shorter tag sizes (4 and 8) are not supported.
//

// pub struct _SYMCRYPT_GCM_EXPANDED_KEY {
//     pub ghashKey: SYMCRYPT_GHASH_EXPANDED_KEY,
//     pub pBlockCipher: PCSYMCRYPT_BLOCKCIPHER,
//     pub __bindgen_padding_0: u64,
//     pub blockcipherKey: SYMCRYPT_GCM_SUPPORTED_BLOCKCIPHER_KEYS,
//     pub cbKey: SIZE_T,
//     pub abKey: [BYTE; 32usize],
//     pub magic: SIZE_T,
// }


// extern "C" {
//     pub fn SymCryptGcmExpandKey(
//         pExpandedKey: PSYMCRYPT_GCM_EXPANDED_KEY,
//         pBlockCipher: PCSYMCRYPT_BLOCKCIPHER,
//         pbKey: PCBYTE,
//         cbKey: SIZE_T,
//     ) -> SYMCRYPT_ERROR;
// }

// extern "C" {
//     pub fn SymCryptGcmEncrypt(
//         pExpandedKey: PCSYMCRYPT_GCM_EXPANDED_KEY,
//         pbNonce: PCBYTE,
//         cbNonce: SIZE_T,
//         pbAuthData: PCBYTE,
//         cbAuthData: SIZE_T,
//         pbSrc: PCBYTE,
//         pbDst: PBYTE,
//         cbData: SIZE_T,
//         pbTag: PBYTE,
//         cbTag: SIZE_T,
//     );
// }