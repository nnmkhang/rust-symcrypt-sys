use core::ffi::c_void;
use std::mem;
use std::ptr;
use symcrypt_sys;

pub const SHA256_RESULT_SIZE: usize = symcrypt_sys::SYMCRYPT_SHA256_RESULT_SIZE as usize;
pub const SHA384_RESULT_SIZE: usize = symcrypt_sys::SYMCRYPT_SHA384_RESULT_SIZE as usize;

pub struct Sha256State {
    state: symcrypt_sys::SYMCRYPT_SHA256_STATE,
}

impl Sha256State {
    pub fn new() -> Self {
        let mut instance = Sha256State {
            state: symcrypt_sys::SYMCRYPT_SHA256_STATE::default(),
        };
        unsafe {
            symcrypt_sys::SymCryptSha256Init(&mut instance.state);
        }
        instance
    }

    pub fn append(&mut self, data: &[u8]) {
        unsafe {
            symcrypt_sys::SymCryptSha256Append(
                &mut self.state,                    // pState
                data.as_ptr(),                      // pbData
                data.len() as symcrypt_sys::SIZE_T, // cbData
            );
        }
    }

    pub fn result(&mut self, result: &mut [u8; SHA256_RESULT_SIZE]) {
        unsafe {
            symcrypt_sys::SymCryptSha256Result(&mut self.state, result.as_mut_ptr());
        }
    }
}

impl Drop for Sha256State {
    fn drop(&mut self) {
        unsafe {
            symcrypt_sys::SymCryptWipe(
                ptr::addr_of_mut!(self.state) as *mut c_void,
                mem::size_of_val(&mut self.state) as symcrypt_sys::SIZE_T,
            )
        }
    }
}

pub fn sha256(data: &[u8], result: &mut [u8; SHA256_RESULT_SIZE]) {
    unsafe {
        symcrypt_sys::SymCryptSha256(
            data.as_ptr(),                      // pbData
            data.len() as symcrypt_sys::SIZE_T, // cbData
            result.as_mut_ptr(),                // pbResult
        );
    }
}

pub struct Sha384State {
    state: symcrypt_sys::SYMCRYPT_SHA384_STATE,
}

impl Sha384State {
    pub fn new() -> Self {
        let mut instance = Sha384State {
            state: symcrypt_sys::SYMCRYPT_SHA384_STATE::default(),
        };
        unsafe {
            symcrypt_sys::SymCryptSha384Init(&mut instance.state);
        }
        instance
    }

    pub fn append(&mut self, data: &[u8]) {
        unsafe {
            symcrypt_sys::SymCryptSha384Append(
                &mut self.state,                    // pState
                data.as_ptr(),                      // pbData
                data.len() as symcrypt_sys::SIZE_T, // cbData
            );
        }
    }

    pub fn result(&mut self, result: &mut [u8; SHA384_RESULT_SIZE]) {
        unsafe {
            symcrypt_sys::SymCryptSha384Result(&mut self.state, result.as_mut_ptr());
        }
    }
}

impl Drop for Sha384State {
    fn drop(&mut self) {
        unsafe {
            symcrypt_sys::SymCryptWipe(
                ptr::addr_of_mut!(self.state) as *mut c_void,
                mem::size_of_val(&mut self.state) as symcrypt_sys::SIZE_T,
            )
        }
    }
}

pub fn sha384(data: &[u8], result: &mut [u8; SHA384_RESULT_SIZE]) {
    unsafe {
        symcrypt_sys::SymCryptSha384(
            data.as_ptr(),                      // pbData
            data.len() as symcrypt_sys::SIZE_T, // cbData
            result.as_mut_ptr(),                // pbResult
        );
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use std::mem::size_of;
    use symcrypt_sys::{SymCryptSha256Algorithm, SymCryptSha384Algorithm};

    fn check_hash_size(hash: symcrypt_sys::PCSYMCRYPT_HASH) -> symcrypt_sys::SIZE_T {
        let mut result: symcrypt_sys::SIZE_T = 0;
        unsafe {
            result = symcrypt_sys::SymCryptHashStateSize(hash);
        }
        result
    }

    #[test]
    fn stateless_sha256_hash() {
        let data = hex::decode("641ec2cf711e").unwrap();
        let expected: &str = "cfdbd6c9acf9842ce04e8e6a0421838f858559cf22d2ea8a38bd07d5e4692233";

        let mut result: [u8; SHA256_RESULT_SIZE] = [0; SHA256_RESULT_SIZE];
        sha256(&data, &mut result);
        assert_eq!(hex::encode(result), expected);
    }

    #[test]
    fn state_sha256_hash() {
        let data = hex::decode("").unwrap();
        let expected: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

        let mut sha_test = Sha256State::new();
        let mut result: [u8; SHA256_RESULT_SIZE] = [0; SHA256_RESULT_SIZE];
        Sha256State::append(&mut sha_test, &data);
        Sha256State::result(&mut sha_test, &mut result);
        assert_eq!(hex::encode(result), expected);
    }

    #[test]
    fn stateless_sha384_hash() {
        let data = hex::decode("").unwrap();
        let expected: &str = "38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b";

        let mut result: [u8; SHA384_RESULT_SIZE] = [0; SHA384_RESULT_SIZE];
        sha384(&data, &mut result);
        assert_eq!(hex::encode(result), expected);
    }

    #[test]
    fn state_sha384_hash() {
        let data = hex::decode("f268267bfb73d5417ac2bc4a5c64").unwrap();
        let expected: &str = "6f246b1f839e73e585c6356c01e9878ff09e9904244ed0914edb4dc7dbe9ceef3f4695988d521d14d30ee40b84a4c3c8";

        let mut sha_test = Sha384State::new();
        let mut result: [u8; SHA384_RESULT_SIZE] = [0; SHA384_RESULT_SIZE];
        Sha384State::append(&mut sha_test, &data);
        Sha384State::result(&mut sha_test, &mut result);
        assert_eq!(hex::encode(result), expected);
    }

    #[test]
    fn check_state_size() {
        unsafe {
            assert_eq!(
                check_hash_size(SymCryptSha256Algorithm),
                size_of::<Sha256State>() as u64
            );
            assert_eq!(
                check_hash_size(SymCryptSha384Algorithm),
                size_of::<Sha384State>() as u64
            );
        }
    }
}
