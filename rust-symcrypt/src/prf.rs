/* TLS 1.2 Key Derivation PseudoRandomFunctions. For further documentation please refer to symcrypt.h */

use crate::mac_algorithms::*;
use crate::errors::SymCryptError;
use symcrypt_sys;

pub fn prf_expand_key(
    key: &[u8],
    mac_algo: MacAlgorithmType
) -> Result<symcrypt_sys::SYMCRYPT_TLSPRF1_2_EXPANDED_KEY, SymCryptError> {
    // will this not work? might have box return since memory will change
    let mut expanded_key = symcrypt_sys::SYMCRYPT_TLSPRF1_2_EXPANDED_KEY::default();
    unsafe {
        // SAFETY: FFI calls
        match symcrypt_sys::SymCryptTlsPrf1_2ExpandKey(
            &mut expanded_key,
            convert_mac(mac_algo),
            key.as_ptr(),
            key.len() as symcrypt_sys::SIZE_T,
        ) {
            symcrypt_sys::SYMCRYPT_ERROR_SYMCRYPT_NO_ERROR => Ok(expanded_key),
            err => Err(err.into()),
        }
    }
}

pub fn prf_derive(
    expanded_key: symcrypt_sys::SYMCRYPT_TLSPRF1_2_EXPANDED_KEY,
    label: &[u8],
    seed: &[u8],
) -> Result<Vec<u8>, SymCryptError> {
    // might have to box expanded_key if theres magic

    let mut res = vec![0u8]; // what is the length here?

    unsafe {
        // SAFETY: FFI calls
        match symcrypt_sys::SymCryptTlsPrf1_2Derive(
            &expanded_key,
            label.as_ptr(),
            label.len() as symcrypt_sys::SIZE_T,
            seed.as_ptr(),
            seed.len() as symcrypt_sys::SIZE_T,
            res.as_mut_ptr(),
            res.len() as symcrypt_sys::SIZE_T,
        ) {
            symcrypt_sys::SYMCRYPT_ERROR_SYMCRYPT_NO_ERROR => Ok(res),
            err => Err(err.into()),
        }
    }
}

pub fn prf(
    mac_algo: MacAlgorithmType,
    key: &[u8],
    label: &[u8],
    seed: &[u8],
) -> Result<Vec<u8>, SymCryptError> {
    // might have to box expanded_key if theres magic
    let mut res = vec![0u8]; // what is the length here?

    unsafe {
        // SAFETY: FFI calls
        match symcrypt_sys::SymCryptTlsPrf1_2(
            convert_mac(mac_algo),
            key.as_ptr(),
            key.len() as symcrypt_sys::SIZE_T,
            label.as_ptr(),
            label.len() as symcrypt_sys::SIZE_T,
            seed.as_ptr(),
            seed.len() as symcrypt_sys::SIZE_T,
            res.as_mut_ptr(),
            res.len() as symcrypt_sys::SIZE_T,
        ) {
            symcrypt_sys::SYMCRYPT_ERROR_SYMCRYPT_NO_ERROR => Ok(res),
            err => Err(err.into()),
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_prf_expand_key() {
        let p_key = hex::decode("a5e2642633f5b8c81ad3fe0c2fe3a8e5ef806b06121dd10df4bb0fe857bfdcf522558e05d2682c9a80c741a3aab1716f").unwrap();
        let expected = "10fd89ef689c7ef033387b8a8f3e5e8e7c11f680f6bdd71fbac3246a73e98d45d03185dde686e6b2369e4503e9dc5a6d2cee3e2bf2fa3f41d3de57dff3e197c8a9d5f74cc2d277119d894f8584b07a0a5822f0bd68b3433ec6adaf5c9406c5f3ddbb71bbe17ce98f3d4d5893d3179ef369f57aad908e2bf710639100c3ce7e0c";
        let mac_algo = MacAlgorithmType::HmacSha256;
        let res = prf_expand_key(&p_key, mac_algo).unwrap();  

        let res2 = prf_derive(res, )

    }


    // #[TLS 1.2, SHA-256]
    // #[pre-master secret length = 384]
    // #[key block length = 1024]
    
    // [TlsPrf1_2HmacSha256]
    
    // COUNT = 0
    // pre_master_secret = f8938ecc9edebc5030c0c6a441e213cd24e6f770a50dda07876f8d55da062bcadb386b411fd4fe4313a604fce6c17fbc
    // serverHello_random = f6c9575ed7ddd73e1f7d16eca115415812a43c2b747daaaae043abfb50053fce
    // clientHello_random = 36c129d01a3200894b9179faac589d9835d58775f9b5ea3587cb8fd0364cae8c
    // server_random = ae6c806f8ad4d80784549dff28a4b58fd837681a51d928c3e30ee5ff14f39868
    // client_random = 62e1fd91f23f558a605f28478c58cf72637b89784d959df7e946d3f07bd1b616
    // master_secret = 202c88c00f84a17a20027079604787461176455539e705be730890602c289a5001e34eeb3a043e5d52a65e66125188bf
    // key_block = d06139889fffac1e3a71865f504aa5d0d2a2e89506c6f2279b670c3e1b74f531016a2530c51a3a0f7e1d6590d0f0566b2f387f8d11fd4f731cdd572d2eae927f6f2f81410b25e6960be68985add6c38445ad9f8c64bf8068bf9a6679485d966f1ad6f68b43495b10a683755ea2b858d70ccac7ec8b053c6bd41ca299d4e51928


//     #[TLS 1.2, SHA-384]
// #[pre-master secret length = 384]
// #[key block length = 1024]

// [TlsPrf1_2HmacSha384]

// COUNT = 0
// pre_master_secret = a5e2642633f5b8c81ad3fe0c2fe3a8e5ef806b06121dd10df4bb0fe857bfdcf522558e05d2682c9a80c741a3aab1716f
// serverHello_random = cb6e0b3eb02976b6466dfa9651c2919414f1648fd3a7838d02153e5bd39535b6
// clientHello_random = abe4bf5527429ac8eb13574d2709e8012bd1a113c6d3b1d3aa2c3840518778ac
// server_random = 1b1c8568344a65c30828e7483c0e353e2c68641c9551efae6927d9cd627a107c
// client_random = 954b5fe1849c2ede177438261f099a2fcd884d001b9fe1de754364b1f6a6dd8e
// master_secret = b4d49bfa87747fe815457bc3da15073d6ac73389e703079a3503c09e14bd559a5b3c7c601c7365f6ea8c68d3d9596827
// key_block = 10fd89ef689c7ef033387b8a8f3e5e8e7c11f680f6bdd71fbac3246a73e98d45d03185dde686e6b2369e4503e9dc5a6d2cee3e2bf2fa3f41d3de57dff3e197c8a9d5f74cc2d277119d894f8584b07a0a5822f0bd68b3433ec6adaf5c9406c5f3ddbb71bbe17ce98f3d4d5893d3179ef369f57aad908e2bf710639100c3ce7e0c



// const BYTE SymCryptTestMsg3 [ 3] = { 'a', 'b', 'c' };

// const BYTE SymCryptTestKey32[32] = {
//      0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15,
//     16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31,
// };

// const BYTE SymCryptTestMsg16[16] = {
//     0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff 
// };



// static const BYTE pbResult1_1[] =
// {
//     0x8e, 0x7e, 0x7b, 0x2f, 0x7d, 0x00, 0x77, 0x09, 0x78, 0x22, 0x51, 0xf2, 0xcf,
// };

// static const BYTE pbResult1_2Sha512[] =
// {
//     0xf9, 0x9f, 0x44, 0x4d, 0x26, 0xde, 0x8b, 0x4f, 0xc2, 0x81, 0x5b, 0x23, 0x70,
// };




    #[test]
    fn test_prf_expand_key_fail() {}

    #[test]
    fn test_prf_derive() {}

    #[test]
    fn test_prf_derive_fail() {}

    #[test]
    fn test_prf() {}

    #[test]
    fn test_prf_fail() {}
}
