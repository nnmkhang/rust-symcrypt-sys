use symcrypt_sys;
use core::ffi::c_void;
use std::{ptr};
use std::mem;

pub const SHA256_RESULT_SIZE: usize = symcrypt_sys::SYMCRYPT_SHA256_RESULT_SIZE as usize;
pub const SHA384_RESULT_SIZE: usize = symcrypt_sys::SYMCRYPT_SHA384_RESULT_SIZE as usize;


pub struct SymCryptInit;
impl SymCryptInit {
    pub fn new () {
        unsafe { 
            //symcrypt_sys::SymCryptInit(); 
            // TODO: Find out why SymCryptInit() breaks on linux / windows (BREAKING)
        }
    }
}

pub struct Sha256State {
    state: symcrypt_sys::_SYMCRYPT_SHA256_STATE,
    is_dirty: bool
} 

impl Sha256State { // Sha256State 
    pub fn new() -> Self {
            let mut instance = Sha256State {
                state: symcrypt_sys::_SYMCRYPT_SHA256_STATE::default(),
                is_dirty: false
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
        self.is_dirty = true;
    }

    pub fn result(&mut self, result: &mut [u8; SHA256_RESULT_SIZE]) {
        unsafe {
            symcrypt_sys::SymCryptSha256Result(&mut self.state, result.as_mut_ptr());
        }
        self.is_dirty = false;
    }
}

impl Drop for Sha256State {
    fn drop(&mut self) {
        if self.is_dirty {
            unsafe {
                symcrypt_sys::SymCryptWipe( 
                ptr::addr_of_mut!(self.state) as *mut c_void, 
                mem::size_of_val(&mut self.state) as symcrypt_sys::SIZE_T)
            }
        }
    }
}

pub fn sha256(data: &[u8], result: &mut [u8; SHA256_RESULT_SIZE]) {
    unsafe {
        symcrypt_sys::SymCryptSha256(
            data.as_ptr(), // pbData
            data.len() as symcrypt_sys::SIZE_T, // cbData
            result.as_mut_ptr(), // pbResult
        );
    }
}

pub struct Sha384State {
    state: symcrypt_sys::_SYMCRYPT_SHA384_STATE,
    is_dirty: bool
}

impl Sha384State {
    pub fn new() -> Self {
        let mut instance = Sha384State {
            state: symcrypt_sys::_SYMCRYPT_SHA384_STATE::default(),
            is_dirty: false
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
        self.is_dirty = true;
    }

    pub fn result(&mut self, result: &mut [u8; SHA384_RESULT_SIZE]) {
        unsafe {
            symcrypt_sys::SymCryptSha384Result(&mut self.state, result.as_mut_ptr());
        }
        self.is_dirty = false;
    }
}

impl Drop for Sha384State {
    fn drop(&mut self) {
        if self.is_dirty {
            unsafe {
                symcrypt_sys::SymCryptWipe(
                ptr::addr_of_mut!(self.state) as *mut c_void,
                mem::size_of_val(&mut self.state) as symcrypt_sys::SIZE_T)
            }
        }
    }
}

pub fn sha384(data: &[u8], result: &mut [u8; SHA384_RESULT_SIZE]) {
    unsafe {
        symcrypt_sys::SymCryptSha384(
            data.as_ptr(), // pbData
            data.len() as symcrypt_sys::SIZE_T, // cbData
            result.as_mut_ptr(), // pbResult
        );
    }
}

// Utility Functions
pub fn check_hash_size(hash: symcrypt_sys::PCSYMCRYPT_HASH) -> symcrypt_sys::SIZE_T {
    let mut result: symcrypt_sys::SIZE_T = 0;
    unsafe {
        result = symcrypt_sys::SymCryptHashStateSize(hash); //pHash
    }
    result
}
