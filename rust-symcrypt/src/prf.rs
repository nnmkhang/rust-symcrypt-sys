/* TLS 1.2 Key Derivation PseudoRandomFunctions. For further documentation please refer to symcrypt.h */

use crate::errors::SymCryptError;
use symcrypt_sys;

pub fn prf_expand_key(
    key: &[u8],
) -> Result<symcrypt_sys::SYMCRYPT_TLSPRF1_2_EXPANDED_KEY, SymCryptError> {
    // will this not work? might have box return since memory will change
    let mut expanded_key = symcrypt_sys::SYMCRYPT_TLSPRF1_2_EXPANDED_KEY::default();
    let mac_algo = symcrypt_sys::SYMCRYPT_MAC::default(); // change this to what its actually supposed to be
    unsafe {
        // SAFETY: FFI calls
        match symcrypt_sys::SymCryptTlsPrf1_2ExpandKey(
            &mut expanded_key,
            &mac_algo,
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
    mac_algo: symcrypt_sys::SYMCRYPT_MAC,
    key: &[u8],
    label: &[u8],
    seed: &[u8],
) -> Result<Vec<u8>, SymCryptError> {
    // might have to box expanded_key if theres magic
    let mut res = vec![0u8]; // what is the length here?

    unsafe {
        // SAFETY: FFI calls
        match symcrypt_sys::SymCryptTlsPrf1_2(
            &mac_algo,
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
    fn test_prf_expand_key() {}

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
