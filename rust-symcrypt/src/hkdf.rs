/* TLS 1.3 HMAC-based Key Derivation Functions. For further documentation please refer to symcrypt.h */

use crate::errors::SymCryptError;
use symcrypt_sys;

pub fn hkdf_expand_key( // might need magic
    mac_algo: symcrypt_sys::SYMCRYPT_MAC,
    ikm: &[u8],
    salt: Option<&[u8]>,
) -> Result<symcrypt_sys::SYMCRYPT_HKDF_EXPANDED_KEY, SymCryptError> {
    // check salt return type, take in
    let mut expanded_key = symcrypt_sys::SYMCRYPT_HKDF_EXPANDED_KEY::default();
    let mac_algo = symcrypt_sys::SYMCRYPT_MAC::default(); // change

    let (salt_ptr, salt_len) = salt.map_or_else(
        || (std::ptr::null(), 0 as symcrypt_sys::SIZE_T),
        |data| (data.as_ptr(), data.len() as symcrypt_sys::SIZE_T),
    );

    unsafe {
        // SAFETY: FFI calls
        match symcrypt_sys::SymCryptHkdfExpandKey(
            &mut expanded_key,
            &mac_algo,
            ikm.as_ptr(),
            ikm.len() as symcrypt_sys::SIZE_T,
            salt_ptr,
            salt_len,
        ) {
            symcrypt_sys::SYMCRYPT_ERROR_SYMCRYPT_NO_ERROR => Ok(expanded_key),
            err => Err(err.into()),
        }
    }
}

pub fn hkdf_extract_prk(
    mac_algo: symcrypt_sys::SYMCRYPT_MAC,
    ikm: &[u8],
    salt: Option<&[u8]>,
) -> Result<Vec<u8>, SymCryptError> {
    // check salt return type, take in
    let mut res = vec![0u8]; // what is the length here?

    let (salt_ptr, salt_len) = salt.map_or_else(
        || (std::ptr::null(), 0 as symcrypt_sys::SIZE_T),
        |data| (data.as_ptr(), data.len() as symcrypt_sys::SIZE_T),
    );

    unsafe {
        // SAFETY: FFI calls
        match symcrypt_sys::SymCryptHkdfExtractPrk(
            &mac_algo,
            ikm.as_ptr(),
            ikm.len() as symcrypt_sys::SIZE_T,
            salt_ptr,
            salt_len,
            res.as_mut_ptr(),
            res.len() as symcrypt_sys::SIZE_T,
        ) {
            symcrypt_sys::SYMCRYPT_ERROR_SYMCRYPT_NO_ERROR => Ok(res),
            err => Err(err.into()),
        }
    }
}

pub fn hkdf_prk_expand_key(
    mac_algo: symcrypt_sys::SYMCRYPT_MAC, // figure out mac_algo
    prk: &[u8],
) -> Result<symcrypt_sys::SYMCRYPT_HKDF_EXPANDED_KEY, SymCryptError> {
    let mut expanded_key = symcrypt_sys::SYMCRYPT_HKDF_EXPANDED_KEY::default();
    let mac_algo = symcrypt_sys::SYMCRYPT_MAC::default(); // change

    unsafe {
        // SAFETY: FFI calls
        match symcrypt_sys::SymCryptHkdfPrkExpandKey(
            &mut expanded_key,
            &mac_algo,
            prk.as_ptr(),
            prk.len() as symcrypt_sys::SIZE_T,
        ) {
            symcrypt_sys::SYMCRYPT_ERROR_SYMCRYPT_NO_ERROR => Ok(expanded_key),
            err => Err(err.into()),
        }
    }
}

pub fn hkdf_derive(
    expanded_key: symcrypt_sys::SYMCRYPT_HKDF_EXPANDED_KEY,
    info: Option<&[u8]>,
) -> Result<Vec<u8>, SymCryptError> {
    let mut res = vec![0u8]; // figure out return length for vector

    let (info_ptr, info_len) = info.map_or_else(
        || (std::ptr::null(), 0 as symcrypt_sys::SIZE_T),
        |data| (data.as_ptr(), data.len() as symcrypt_sys::SIZE_T),
    );

    unsafe {
        // SAFETY: FFI calls
        match symcrypt_sys::SymCryptHkdfDerive(
            &expanded_key,
            info_ptr,
            info_len,
            res.as_mut_ptr(),
            res.len() as symcrypt_sys::SIZE_T,
        ) {
            symcrypt_sys::SYMCRYPT_ERROR_SYMCRYPT_NO_ERROR => Ok(res),
            err => Err(err.into()),
        }
    }
}

pub fn hkdf(
    mac_algo: symcrypt_sys::SYMCRYPT_MAC,
    ikm: &[u8],
    salt: Option<&[u8]>,
    info: Option<&[u8]>,
) -> Result<Vec<u8>, SymCryptError> {
    let mut res = vec![0u8]; // figure out return length for vector

    let (info_ptr, info_len) = info.map_or_else(
        || (std::ptr::null(), 0 as symcrypt_sys::SIZE_T),
        |data| (data.as_ptr(), data.len() as symcrypt_sys::SIZE_T),
    );

    let (salt_ptr, salt_len) = salt.map_or_else(
        || (std::ptr::null(), 0 as symcrypt_sys::SIZE_T),
        |data| (data.as_ptr(), data.len() as symcrypt_sys::SIZE_T),
    );

    unsafe {
        // SAFETY: FFI calls
        match symcrypt_sys::SymCryptHkdf(
            &mac_algo,
            ikm.as_ptr(),
            ikm.len() as symcrypt_sys::SIZE_T,
            salt_ptr,
            salt_len,
            info_ptr,
            info_len,
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
    fn test_hkdf_expand_key() {

    }

    #[test]
    fn test_hkdf_expand_key_fail() {
        
    }

    #[test]
    fn test_hkdf_extract_prk() {

    }

    #[test]
    fn test_hkdf_extract_prk_fail() {
        
    }

    #[test]
    fn test_hkdf_prk_expand_key() {

    }

    #[test]
    fn test_hkdf_prk_expand_key_fail() {
        
    }

    #[test]
    fn test_hkdf_derive() {

    }

    #[test]
    fn test_hkdf_derive_fail() {
        
    }

    #[test]
    fn test_hkdf() {

    }

    #[test]
    fn test_hkdf_fail() {
        
    }
}