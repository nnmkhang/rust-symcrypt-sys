/* Hashing functions. For further documentation please refer to symcrypt.h */

use core::ffi::c_void;
use std::mem;
use std::ptr;
use symcrypt_sys;
use std::pin::Pin;

pub const SHA256_RESULT_SIZE: usize = symcrypt_sys::SYMCRYPT_SHA256_RESULT_SIZE as usize;
pub const SHA384_RESULT_SIZE: usize = symcrypt_sys::SYMCRYPT_SHA384_RESULT_SIZE as usize;


/// Enum for HashAlgorithms that are currently available
#[derive(PartialEq, Debug)]
pub enum HashAlgorithms {
    SHA256,
    SHA384,
}

/// Generic trait for hashing
/// 
/// get_output_length() returns the output length for the selected algorithm
/// 
/// new_state() returns a hash object that can perform state operations, see ShaXXXState::new() for more info
/// 
/// get_algorithm() returns the HashAlgorithm that is currently being used 
/// 
/// hash() performs a stateless hash for the current HashAlgorithm. For more info see individual stateless functions; shaXXX()
pub trait Hash {
    type Result;
    type State: HashState<Result = Self::Result>;

    fn get_output_length(&self) -> usize;
    fn new_state(&self) -> Self::State;
    fn get_algorithm(&self) -> HashAlgorithms;
    fn hash(self, data: &[u8]) -> Self::Result;
}

/// Generic trait for stateful hashing
/// 
/// append() appends to be hashed data to the state, this operation can be done multiple times.
/// 
/// result() returns the result of the hash. Once result() is called, the lifetime of the ShaXXXState is finished.
/// To perform other stateful hash operation you must create a new hash object via ShaXXXState::new()
/// 
/// copy() creates a copy of the current ShaXXXState
pub trait HashState {
    type Result;

    fn append(&mut self, data: &[u8]);
    fn result(self) -> Self::Result;
    fn copy(&self) -> Self;
}

/// Hashing trait implementation for Sha256
pub struct Sha256;

impl Hash for Sha256 {

    type Result = [u8; SHA256_RESULT_SIZE];
    type State = Sha256State;

    fn get_output_length(&self) -> usize {
        SHA256_RESULT_SIZE
    }

    fn new_state(&self) -> Sha256State {
        Sha256State::new()
    }

    fn get_algorithm(&self) -> HashAlgorithms {
        HashAlgorithms::SHA256
    }

    fn hash(self, data: &[u8]) -> Self::Result {
        sha256(&data)
    }
}

/// Sha256State needs to have a heap allocated inner state that is Pin<Box<T>> since the memory address of Self is moved around when implementing 
/// HashState Result field.
/// 
/// SymCrypt expects the address for its structs to stay static through the structs lifetime to guarantee that structs are not memcpy'd as
/// doing so would lead to use-after-free and inconsistent states.
pub struct Sha256State {
    state: Pin<Box<Sha256InnerState>>,  
}

struct Sha256InnerState(symcrypt_sys::SYMCRYPT_SHA256_STATE);

/// Creates a new instance of Sha256State, this must be called before other HashState functions can be called
impl Sha256State {
    pub fn new() -> Self {
        let mut instance =  Sha256State {
            state: Box::pin(Sha256InnerState(symcrypt_sys::SYMCRYPT_SHA256_STATE::default())),
        };
        unsafe { // SAFETY: FFI calls
            symcrypt_sys::SymCryptSha256Init(&mut instance.state.0);
        }
        instance
    }
}

impl HashState for Sha256State {
    type Result = [u8; SHA256_RESULT_SIZE];

    fn append(&mut self, data: &[u8]) {
        unsafe { // SAFETY: FFI calls
            symcrypt_sys::SymCryptSha256Append(
                &mut self.state.0,
                data.as_ptr(),
                data.len() as symcrypt_sys::SIZE_T,
            );
        }
    }

    fn result(mut self) -> Self::Result {
        let mut result = [0u8; SHA256_RESULT_SIZE];
        unsafe { // SAFETY: FFI calls
            symcrypt_sys::SymCryptSha256Result(&mut self.state.0, result.as_mut_ptr());
        }
        result
    }

    fn copy(&self) -> Self {
        let mut new_state = Sha256State {
            state: Box::pin(Sha256InnerState(symcrypt_sys::SYMCRYPT_SHA256_STATE::default())),
        };
        unsafe { // SAFETY: FFI calls
            symcrypt_sys::SymCryptSha256StateCopy(&self.state.0, &mut new_state.state.0);
        }
        new_state
    }
}

impl Drop for Sha256State {
    fn drop(&mut self) {
        unsafe { // SAFETY: FFI calls
            symcrypt_sys::SymCryptWipe(
                ptr::addr_of_mut!(self.state) as *mut c_void,
                mem::size_of_val(&mut self.state) as symcrypt_sys::SIZE_T,
            )
        }
    }
}

/// Stateless hash function for SHA256, this can be called alone without the use of the Hash trait
pub fn sha256(data: &[u8]) -> [u8; SHA256_RESULT_SIZE] {
    let mut result = [0; SHA256_RESULT_SIZE];
    unsafe { // SAFETY: FFI calls
        symcrypt_sys::SymCryptSha256(
            data.as_ptr(),
            data.len() as symcrypt_sys::SIZE_T,
            result.as_mut_ptr(),
        );
    }
    result
}

/// Hashing trait implementation for Sha384
pub struct Sha384;

impl Hash for Sha384 {

    type Result = [u8; SHA384_RESULT_SIZE];
    type State = Sha384State;

    fn get_output_length(&self) -> usize {
        SHA384_RESULT_SIZE
    }

    fn new_state(&self) -> Sha384State {
        Sha384State::new()
    }

    fn get_algorithm(&self) -> HashAlgorithms {
        HashAlgorithms::SHA384
    }

    fn hash(self, data: &[u8]) -> Self::Result {
        sha384(&data)
    }
}   

/// Sha384State needs to have a heap allocated inner state that is Pin<Box<T>> since the memory address of Self is moved around when implementing 
/// HashState Result field.
/// 
/// SymCrypt expects the address for its structs to stay static through the structs lifetime to guarantee that structs are not memcpy'd as
/// doing so would lead to use-after-free and inconsistent states.
struct Sha384InnerState(symcrypt_sys::SYMCRYPT_SHA384_STATE);

pub struct Sha384State {
    state: Pin<Box<Sha384InnerState>>,
}

/// Creates a new instance of Sha384State, this must be called before other HashState functions can be called
impl Sha384State {
    pub fn new() -> Self {
        let mut instance = Sha384State {
            state: Box::pin(Sha384InnerState(symcrypt_sys::SYMCRYPT_SHA384_STATE::default())),
        };
        unsafe { // SAFETY: FFI calls
            symcrypt_sys::SymCryptSha384Init(&mut instance.state.0);
        }
        instance
    }
}

impl HashState for Sha384State {
    type Result = [u8; SHA384_RESULT_SIZE];

    fn append(&mut self, data: &[u8]) {
        unsafe { // SAFETY: FFI calls
            symcrypt_sys::SymCryptSha384Append(
                &mut self.state.0,
                data.as_ptr(),
                data.len() as symcrypt_sys::SIZE_T,
            );
        }
    }

    fn result(mut self) -> Self::Result {
        let mut result = [0u8; SHA384_RESULT_SIZE];
        unsafe { // SAFETY: FFI calls
            symcrypt_sys::SymCryptSha384Result(&mut self.state.0, result.as_mut_ptr());
        }
        result
    }

    fn copy(&self) -> Self {
        let mut new_state = Sha384State {
            state: Box::pin(Sha384InnerState(symcrypt_sys::SYMCRYPT_SHA384_STATE::default())),
        };
        unsafe { // SAFETY: FFI calls
            symcrypt_sys::SymCryptSha384StateCopy(&self.state.0, &mut new_state.state.0);
        }
        new_state
    }
}

impl Drop for Sha384State {
    fn drop(&mut self) {
        unsafe { // SAFETY: FFI calls
            symcrypt_sys::SymCryptWipe(
                ptr::addr_of_mut!(self.state) as *mut c_void,
                mem::size_of_val(&mut self.state) as symcrypt_sys::SIZE_T,
            )
        }
    }
}

/// Stateless hash function for SHA384, this can be called alone without the use of the Hash trait
pub fn sha384(data: &[u8]) -> [u8; SHA384_RESULT_SIZE] {
    let mut result = [0; SHA384_RESULT_SIZE];
    unsafe { // SAFETY: FFI calls
        symcrypt_sys::SymCryptSha384(
            data.as_ptr(),
            data.len() as symcrypt_sys::SIZE_T,
            result.as_mut_ptr(),
        );
    }
    result
}

#[cfg(test)]
mod test {
    use super::*;

    fn test_generic_hash_state<H: HashState>(mut hash_state: H, data: &[u8], expected: &str)
    where
        H::Result: AsRef<[u8]>,
    {
        hash_state.append(data);
        let result = hash_state.result();
        assert_eq!(hex::encode(result), expected);
    }

    fn test_generic_state_copy<H: HashState>(mut hash_state: H, data: &[u8])
    where 
        H::Result: AsRef<[u8]>,
    {
        hash_state.append(&data);
        let new_hash_state = hash_state.copy();

        assert_eq!(hex::encode(new_hash_state.result()), hex::encode(hash_state.result()));
    }

    fn test_generic_state_multiple_append<H: HashState>(mut hash_state: H, data_1: &[u8], data_2: &[u8], expected: &str)
    where
        H::Result: AsRef<[u8]>,
    {
        hash_state.append(&data_1);
        hash_state.append(&data_2);

        let result = hash_state.result();
        assert_eq!(hex::encode(result), expected);
    }

    fn test_generic_hash_create_new_state<H: Hash>(hash: H, data: &[u8], expected: &str)
    where
        H::Result: AsRef<[u8]>,
    {
        let mut hash_state = hash.new_state();
        hash_state.append(&data);
        let result = hash_state.result();
        assert_eq!(hex::encode(result), expected);
    }


    fn test_generic_hash_stateless_hash<H: Hash>(hash: H, data: &[u8], expected: &str, alg_type: HashAlgorithms, output_len: usize) 
    where
        H::Result: AsRef<[u8]>,
    {
        let alg = hash.get_algorithm();
        assert_eq!(alg, alg_type);

        let len = hash.get_output_length();
        assert_eq!(len, output_len);

        let result = hash.hash(&data);
        assert_eq!(hex::encode(result), expected);
    }

    #[test]
    fn test_stateless_sha256_hash() {
        let data = hex::decode("641ec2cf711e").unwrap();
        let expected: &str = "cfdbd6c9acf9842ce04e8e6a0421838f858559cf22d2ea8a38bd07d5e4692233";

        let result = sha256(&data);
        assert_eq!(hex::encode(result), expected);
    }

    #[test]
    fn test_hash_trait_sha256() {
        let data = hex::decode("641ec2cf711e").unwrap();
        let expected: &str = "cfdbd6c9acf9842ce04e8e6a0421838f858559cf22d2ea8a38bd07d5e4692233";

        test_generic_hash_create_new_state(Sha256, &data, expected);
    }

    #[test]
    fn test_hash_trait_sha384() {
        let data = hex::decode("").unwrap();
        let expected: &str = "38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b";

        test_generic_hash_create_new_state(Sha384, &data, expected);
    }

    #[test]
    fn test_hash_trait_stateless_sha256() {
        let data = hex::decode("641ec2cf711e").unwrap();
        let expected: &str = "cfdbd6c9acf9842ce04e8e6a0421838f858559cf22d2ea8a38bd07d5e4692233";

        test_generic_hash_stateless_hash(Sha256, &data, expected, HashAlgorithms::SHA256, SHA256_RESULT_SIZE);
    }

    #[test]
    fn test_hash_trait_stateless_sha384() {
        let data = hex::decode("").unwrap();
        let expected: &str = "38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b";

        test_generic_hash_stateless_hash(Sha384, &data, expected, HashAlgorithms::SHA384, SHA384_RESULT_SIZE);
    }

    #[test]
    fn test_state_sha256_hash() {
        let data = hex::decode("").unwrap();
        let expected: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

        test_generic_hash_state(Sha256State::new(), &data, expected);
    }

    #[test]
    fn test_stateless_sha384_hash() {
        let data = hex::decode("").unwrap();
        let expected: &str = "38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b";

        let result = sha384(&data);
        assert_eq!(hex::encode(result), expected);
    }

    #[test]
    fn test_state_sha384_hash() {
        let data = hex::decode("f268267bfb73d5417ac2bc4a5c64").unwrap();
        let expected: &str = "6f246b1f839e73e585c6356c01e9878ff09e9904244ed0914edb4dc7dbe9ceef3f4695988d521d14d30ee40b84a4c3c8";

        test_generic_hash_state(Sha384State::new(), &data, expected);
    }

    #[test]
    fn test_state_sha256_copy() {
        let data = hex::decode("641ec2cf711e").unwrap();
        test_generic_state_copy(Sha256State::new(), &data);
    }

    #[test]
    fn test_state_sha384_copy() {
        let data = hex::decode("f268267bfb73d5417ac2bc4a5c64").unwrap();
        test_generic_state_copy(Sha384State::new(), &data);
    }

    #[test]
    fn test_state_sha256_multiple_append() {
        let data_1 = hex::decode("641ec2").unwrap(); 
        let data_2 = hex::decode("cf711e").unwrap(); 
        let expected: &str = "cfdbd6c9acf9842ce04e8e6a0421838f858559cf22d2ea8a38bd07d5e4692233";

        test_generic_state_multiple_append(Sha256State::new(), &data_1, &data_2, expected);
    }

    #[test]
    fn test_state_sha384_multiple_append() {
        let data_1 = hex::decode("f268267bfb73d5417ac2bc4a5c64").unwrap();
        let data_2 = hex::decode("").unwrap(); 
        let expected: &str = "6f246b1f839e73e585c6356c01e9878ff09e9904244ed0914edb4dc7dbe9ceef3f4695988d521d14d30ee40b84a4c3c8";

        test_generic_state_multiple_append(Sha384State::new(), &data_1, &data_2, expected);
    }
}
