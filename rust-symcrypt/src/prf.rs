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
        unsafe {
            let p_key = hex::decode("a5e2642633f5b8c81ad3fe0c2fe3a8e5ef806b06121dd10df4bb0fe857bfdcf522558e05d2682c9a80c741a3aab1716f").unwrap();
            let expected = "10fd89ef689c7ef033387b8a8f3e5e8e7c11f680f6bdd71fbac3246a73e98d45d03185dde686e6b2369e4503e9dc5a6d2cee3e2bf2fa3f41d3de57dff3e197c8a9d5f74cc2d277119d894f8584b07a0a5822f0bd68b3433ec6adaf5c9406c5f3ddbb71bbe17ce98f3d4d5893d3179ef369f57aad908e2bf710639100c3ce7e0c";
            let mac_algo = MacAlgorithmType::HmacSha256;
            let res = prf_expand_key(&p_key, mac_algo).unwrap();
            
        }
    }

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
