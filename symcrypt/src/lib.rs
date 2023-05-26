use symcrypt_sys::*;
use core::ffi::c_void;

pub const SHA256_LENGTH: usize = 32;
pub const SHA384_LENGTH: usize = 48;


pub struct SymCryptInit;
impl SymCryptInit {
    pub fn new () {
        unsafe { 
            // symcrypt_sys::SymCryptInit(); 
            // TODO: Find out why SymCryptInit() breaks on linux / windows (BREAKING)
        }
    }
}

pub struct Sha256State {
    pub state: symcrypt_sys::_SYMCRYPT_SHA256_STATE
} 

impl Sha256State { // Sha256State 
    pub fn new() -> Self {
            let mut instance = Sha256State {
                state: symcrypt_sys::_SYMCRYPT_SHA256_STATE::default()
            };
            unsafe {
                symcrypt_sys::SymCryptSha256Init(&mut instance.state);
            }
        instance
    }

    pub fn append(&mut self, data: &[u8] ) {
        unsafe {
            symcrypt_sys::SymCryptSha256Append(
                &mut self.state, // pState
                data.as_ptr(), // pbData
                data.len() as symcrypt_sys::SIZE_T, //cbData
            );
        }
    }

    pub fn result(&mut self, result: &mut [u8; SHA256_LENGTH]) {
        unsafe {
            symcrypt_sys::SymCryptSha256Result(&mut self.state, result.as_mut_ptr())
        }
    }
}

impl Drop for Sha256State {
    fn drop(&mut self) {
        // Zero out the memory for state
        unsafe {
            std::ptr::write_volatile(&mut self.state, std::mem::zeroed());
        }
    }
}

pub fn sha256(data: &[u8], result: &mut [u8; SHA256_LENGTH]) {
    unsafe {
        symcrypt_sys::SymCryptSha256(
            data.as_ptr(), // pbData
            data.len() as symcrypt_sys::SIZE_T, // cbData
            result.as_mut_ptr(), // pbResult
        );
    }
}

pub struct Sha384State {
    pub state: symcrypt_sys::_SYMCRYPT_SHA384_STATE
}

impl Sha384State {
    pub fn new() -> Self {
        let mut instance = Sha384State {
            state: symcrypt_sys::_SYMCRYPT_SHA384_STATE::default()
        };
        unsafe {
            symcrypt_sys::SymCryptSha384Init(&mut instance.state);
        }
        instance
    }
    
    pub fn append(&mut self, data: &[u8] ) {
        unsafe {
            symcrypt_sys::SymCryptSha384Append(
                &mut self.state, // pState
                data.as_ptr(), // pbData
                data.len() as symcrypt_sys::SIZE_T, //cbData
            );
        }
    }

    pub fn result(&mut self, result: &mut [u8; SHA384_LENGTH]) {
        unsafe {
            symcrypt_sys::SymCryptSha384Result(&mut self.state, result.as_mut_ptr())
        }
    }
}

impl Drop for Sha384State {
    fn drop(&mut self) {
        // Zero out the memory for state
        unsafe {
            // TODO: switch to SymCryptWipe
            std::ptr::write_volatile(&mut self.state, std::mem::zeroed());
        }
    }
}

pub fn sha384(data: &[u8], result: &mut [u8; SHA384_LENGTH]) {
    unsafe {
        symcrypt_sys::SymCryptSha384(
            data.as_ptr(), // pbData
            data.len() as symcrypt_sys::SIZE_T, // cbData
            result.as_mut_ptr(), // pbResult
        );
    }
}

// For testing
pub fn check_hash_size() -> symcrypt_sys::SIZE_T {
    let mut result: u64 = 0;
    unsafe{
        // symcrypt_sys::SymCryptSha256Algorithm
        result = symcrypt_sys::SymCryptHashStateSize(symcrypt_sys::SymCryptSha256Algorithm); //pHash
        // TODO: Find why this is breaking. Unable to find de-reference pointer
    }
    result
}
