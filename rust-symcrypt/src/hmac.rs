/* Hmac functions. For further documentation please refer to symcrypt.h */

use crate::errors::SymCryptError;
use core::ffi::c_void;
use std::mem;
use std::pin::Pin;
use std::ptr;
use std::sync::Arc;
use symcrypt_sys;

pub const SHA256_HMAC_RESULT_SIZE: usize = symcrypt_sys::SYMCRYPT_SHA256_RESULT_SIZE as usize;
pub const SHA384_HMAC_RESULT_SIZE: usize = symcrypt_sys::SYMCRYPT_SHA384_RESULT_SIZE as usize;

/// Generic trait for stateful Hmac functions
///
/// append() appends data to the HmacShaXXXState, this operation can be done multiple times.
///
/// result() returns the result of the Hmac. Once result() is called, the lifetime of the HmacShaXXXState is
/// finished and HmacShaXXState will be drop()'d. To perform other stateful hash operation you must create
/// a new hash object via HmacShaXXXState::new()
///
/// copy() creates a copy of the current HmacShaXXXState. copy() will create a new state but will reference the same
/// expanded_key of the current HmacShaXXXState; therefore increasing the refcount of the HmacShaXXXExpandedKey struct.
pub trait HmacState {
    type Result;

    fn append(&mut self, data: &[u8]);
    fn result(self) -> Self::Result;
    fn copy(&self) -> Box<Self>;
}

/// Wrapper for the expanded key that is Pin<Box<>>'d because we want to ensure that its memory address is heap allocated and not moved through its lifetime.
struct HmacSha256ExpandedKey(Pin<Box<symcrypt_sys::SYMCRYPT_HMAC_SHA256_EXPANDED_KEY>>);

/// Since HmacSha256ExpandedKey can be referenced multiple times, HmacSha256ExpandedKey must be ref counted and a there needs to be a separate drop()
impl Drop for HmacSha256ExpandedKey {
    fn drop(&mut self) {
        unsafe {
            // SAFETY: FFI calls
            symcrypt_sys::SymCryptWipe(
                ptr::addr_of_mut!(*self.0) as *mut c_void, // * to dereference the Box<>
                mem::size_of_val(&mut *self.0) as symcrypt_sys::SIZE_T, // * to dereference the Box<>
            );
        }
    }
}

/// Using an inner HmacSha256 state that is Pin<Box<>>'d since the memory address for Self is moved around when returning from HmacSha256State::new()
///
/// expanded_key is Arc<>'d to be properly ref counted when calling HmacShaXXXState::copy().
///
/// SymCrypt expects the address for its structs to stay static through the structs lifetime to guarantee that structs are not memcpy'd as
/// doing so would lead to use-after-free and inconsistent states.
pub struct HmacSha256State {
    inner: Pin<Box<HmacSha256Inner>>,
}

struct HmacSha256Inner {
    state: symcrypt_sys::SYMCRYPT_HMAC_SHA256_STATE,
    expanded_key: Arc<HmacSha256ExpandedKey>,
}

unsafe impl Send for HmacSha256Inner {
    // TODO
}

unsafe impl Sync for HmacSha256Inner {
    // TODO
}

impl HmacSha256State {
    pub fn new(key: &[u8]) -> Result<Self, SymCryptError> {
        let mut expanded_key = HmacSha256ExpandedKey(Pin::new(Box::new(
            symcrypt_sys::SYMCRYPT_HMAC_SHA256_EXPANDED_KEY::default()),
        ));
        unsafe {
            // SAFETY: FFI calls
            match symcrypt_sys::SymCryptHmacSha256ExpandKey(
                &mut *expanded_key.0,
                key.as_ptr(),
                key.len() as symcrypt_sys::SIZE_T,
            ) {
                symcrypt_sys::SYMCRYPT_ERROR_SYMCRYPT_NO_ERROR => {
                    let mut instance = HmacSha256State {
                        inner: Box::pin(HmacSha256Inner {
                            state: symcrypt_sys::SYMCRYPT_HMAC_SHA256_STATE::default(),
                            expanded_key: Arc::new(expanded_key),
                        }),
                    };
                    symcrypt_sys::SymCryptHmacSha256Init(
                        &mut instance.inner.state,
                        &*instance.inner.expanded_key.0,
                    );
                    Ok(instance)
                }
                err => Err(err.into()),
            }
        }
    }
}

impl HmacState for HmacSha256State {
    type Result = [u8; SHA256_HMAC_RESULT_SIZE];

    fn append(&mut self, data: &[u8]) {
        unsafe {
            // SAFETY: FFI calls
            symcrypt_sys::SymCryptHmacSha256Append(
                &mut self.inner.state,
                data.as_ptr(),
                data.len() as symcrypt_sys::SIZE_T,
            )
        }
    }

    fn result(mut self) -> Self::Result {
        let mut result = [0u8; SHA256_HMAC_RESULT_SIZE];
        unsafe {
            // SAFETY: FFI calls
            symcrypt_sys::SymCryptHmacSha256Result(&mut self.inner.state, result.as_mut_ptr());
        }
        result
    }

    fn copy(&self) -> Box<Self> {
        let mut new_state = HmacSha256State {
            inner: Box::pin(HmacSha256Inner {
                state: symcrypt_sys::SYMCRYPT_HMAC_SHA256_STATE::default(),
                expanded_key: Arc::clone(&self.inner.expanded_key),
            }),
        };
        unsafe {
            // SAFETY: FFI calls
            symcrypt_sys::SymCryptHmacSha256StateCopy(
                &self.inner.state,
                &*self.inner.expanded_key.0,
                &mut new_state.inner.state,
            );
        }
        Box::new(new_state)
    }
}

impl Drop for HmacSha256State {
    fn drop(&mut self) {
        unsafe {
            // SAFETY: FFI calls
            symcrypt_sys::SymCryptWipe(
                ptr::addr_of_mut!(self.inner.state) as *mut c_void,
                mem::size_of_val(&mut self.inner.state) as symcrypt_sys::SIZE_T,
            );
        }
    }
}

/// Stateless Hmac functions for Sha256
pub fn hmac_sha256(
    key: &[u8],
    data: &[u8],
    result: &mut [u8; SHA256_HMAC_RESULT_SIZE],
) -> Result<(), SymCryptError> {
    unsafe {
        // SAFETY: FFI calls
        let mut expanded_key = HmacSha256ExpandedKey(Pin::new(Box::new(symcrypt_sys::SYMCRYPT_HMAC_SHA256_EXPANDED_KEY::default())));
        match symcrypt_sys::SymCryptHmacSha256ExpandKey(
            &mut *expanded_key.0,
            key.as_ptr(),
            key.len() as symcrypt_sys::SIZE_T,
        ) {
            symcrypt_sys::SYMCRYPT_ERROR_SYMCRYPT_NO_ERROR => {
                symcrypt_sys::SymCryptHmacSha256(
                    &mut *expanded_key.0,
                    data.as_ptr(),
                    data.len() as symcrypt_sys::SIZE_T,
                    result.as_mut_ptr(),
                );
                Ok(())
            }
            err => Err(err.into()),
        }
    }
}

/// Wrapper for the expanded key that is Pin<Box<>>'d because we want to ensure that its memory address is heap allocated and not moved through its lifetime.
struct HmacSha384ExpandedKey(Pin<Box<symcrypt_sys::SYMCRYPT_HMAC_SHA384_EXPANDED_KEY>>);

/// Since HmacSha384ExpandedKey can be referenced multiple times, HmacSha384ExpandedKey must be ref counted and a there needs to be a separate drop()
impl Drop for HmacSha384ExpandedKey {
    fn drop(&mut self) {
        unsafe {
            // SAFETY: FFI calls
            symcrypt_sys::SymCryptWipe(
                ptr::addr_of_mut!(*self.0) as *mut c_void,
                mem::size_of_val(&mut *self.0) as symcrypt_sys::SIZE_T,
            );
        }
    }
}

/// Using an inner HmacSha384 state that is Pin<Box<>>'d since the memory address for Self is moved around when returning from HmacSha384State::new()
///
/// expanded_key is Arc<>'d to be properly ref counted when calling HmacShaXXXState::copy().
///
/// SymCrypt expects the address for its structs to stay static through the structs lifetime to guarantee that structs are not memcpy'd as
/// doing so would lead to use-after-free and inconsistent states.
pub struct HmacSha384State {
    inner: Pin<Box<HmacSha384Inner>>,
}

struct HmacSha384Inner {
    state: symcrypt_sys::SYMCRYPT_HMAC_SHA384_STATE,
    expanded_key: Arc<HmacSha384ExpandedKey>,
}

unsafe impl Send for HmacSha384Inner {
    // TODO
}

unsafe impl Sync for HmacSha384Inner {
    // TODO
}

impl HmacSha384State {
    pub fn new(key: &[u8]) -> Result<Self, SymCryptError> {
        let mut expanded_key = HmacSha384ExpandedKey(Pin::new(Box::new(
            symcrypt_sys::SYMCRYPT_HMAC_SHA384_EXPANDED_KEY::default()),
        ));
        unsafe {
            // SAFETY: FFI calls
            match symcrypt_sys::SymCryptHmacSha384ExpandKey(
                &mut *expanded_key.0,
                key.as_ptr(),
                key.len() as symcrypt_sys::SIZE_T,
            ) {
                symcrypt_sys::SYMCRYPT_ERROR_SYMCRYPT_NO_ERROR => {
                    let mut instance = HmacSha384State {
                        inner: Box::pin(HmacSha384Inner {
                            state: symcrypt_sys::SYMCRYPT_HMAC_SHA384_STATE::default(),
                            expanded_key: Arc::new(expanded_key),
                        }),
                    };
                    symcrypt_sys::SymCryptHmacSha384Init(
                        &mut instance.inner.state,
                        &*instance.inner.expanded_key.0,
                    );
                    Ok(instance)
                }
                err => Err(err.into()),
            }
        }
    }
}

impl HmacState for HmacSha384State {
    type Result = [u8; SHA384_HMAC_RESULT_SIZE];

    fn append(&mut self, data: &[u8]) {
        unsafe {
            // SAFETY: FFI calls
            symcrypt_sys::SymCryptHmacSha384Append(
                &mut self.inner.state,
                data.as_ptr(),
                data.len() as symcrypt_sys::SIZE_T,
            )
        }
    }

    fn result(mut self) -> Self::Result {
        let mut result = [0u8; SHA384_HMAC_RESULT_SIZE];
        unsafe {
            // SAFETY: FFI calls
            symcrypt_sys::SymCryptHmacSha384Result(&mut self.inner.state, result.as_mut_ptr());
        }
        result
    }

    fn copy(&self) -> Box<Self> {
        let mut new_state = HmacSha384State {
            inner: Box::pin(HmacSha384Inner {
                state: symcrypt_sys::SYMCRYPT_HMAC_SHA384_STATE::default(),
                expanded_key: Arc::clone(&self.inner.expanded_key),
            }),
        };
        unsafe {
            // SAFETY: FFI calls
            symcrypt_sys::SymCryptHmacSha384StateCopy(
                &self.inner.state,
                &*self.inner.expanded_key.0,
                &mut new_state.inner.state,
            );
        }
        Box::new(new_state)
    }
}

impl Drop for HmacSha384State {
    fn drop(&mut self) {
        unsafe {
            // SAFETY: FFI calls
            symcrypt_sys::SymCryptWipe(
                ptr::addr_of_mut!(self.inner.state) as *mut c_void,
                mem::size_of_val(&mut self.inner.state) as symcrypt_sys::SIZE_T,
            );
        }
    }
}

/// Stateless Hmac functions for Sha384
pub fn hmac_sha384(
    key: &[u8],
    data: &[u8],
    result: &mut [u8; SHA384_HMAC_RESULT_SIZE],
) -> Result<(), SymCryptError> {
    unsafe {
        // SAFETY: FFI calls
        let mut expanded_key = HmacSha384ExpandedKey(Pin::new(Box::new(symcrypt_sys::SYMCRYPT_HMAC_SHA384_EXPANDED_KEY::default())));
        match symcrypt_sys::SymCryptHmacSha384ExpandKey(
            &mut *expanded_key.0,
            key.as_ptr(),
            key.len() as symcrypt_sys::SIZE_T,
        ) {
            symcrypt_sys::SYMCRYPT_ERROR_SYMCRYPT_NO_ERROR => {
                symcrypt_sys::SymCryptHmacSha384(
                    &mut *expanded_key.0,
                    data.as_ptr(),
                    data.len() as symcrypt_sys::SIZE_T,
                    result.as_mut_ptr(),
                );
                Ok(())
            }
            err => Err(err.into()),
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    fn test_generic_hmac_state<H: HmacState>(mut hmac_state: H, data: &[u8], expected: &str)
    where
        H::Result: AsRef<[u8]>,
    {
        hmac_state.append(data);
        let result = hmac_state.result();
        assert_eq!(hex::encode(result), expected);
    }

    fn test_generic_state_copy<H: HmacState>(mut hmac_state: H, data: &[u8])
    where
        H::Result: AsRef<[u8]>,
    {
        hmac_state.append(&data);
        let new_hmac_state = hmac_state.copy();

        let result = new_hmac_state.result();
        assert_eq!(hex::encode(result), hex::encode(hmac_state.result()));
    }

    fn test_generic_state_multiple_append<H: HmacState>(
        mut hmac_state: H,
        data_1: &[u8],
        data_2: &[u8],
        expected: &str,
    ) where
        H::Result: AsRef<[u8]>,
    {
        hmac_state.append(&data_1);
        hmac_state.append(&data_2);

        let result = hmac_state.result();
        assert_eq!(hex::encode(result), expected);
    }

    #[test]
    pub fn test_hmac_sha256() {
        let p_key = hex::decode("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b").unwrap();
        let data = hex::decode("").unwrap();
        let expected = "915cb2c078aaf5dfb3560cf6d96997e987b2de5cd46f9a2ef92493bfc34bab16";

        let hmac_test = HmacSha256State::new(&p_key).unwrap();
        test_generic_hmac_state(hmac_test, &data, expected)
    }

    #[test]
    pub fn test_hmac_sha256_state_copy() {
        let p_key = hex::decode("0a71d5cf99849bc13d73832dcd864244").unwrap();
        let data = hex::decode("17f1ee0c6767a1f3f04bb3c1b7a4e0d4f0e59e5963c1a3bf1540a76b25136baef425faf488722e3e331c77d26fbbd8300df532498f50c5ecd243f481f09348f964ddb8056f6e2886bb5b2f453fcf1de5629f3d166324570bf849792d35e3f711b041b1a7e30494b5d1316484ed85b8da37094627a8e66003d079bfd8beaa80dc").unwrap();

        let hmac_state = HmacSha256State::new(&p_key).unwrap();
        test_generic_state_copy(hmac_state, &data);
    }

    #[test]
    fn test_hmac_sha256_multiple_append() {
        let p_key = hex::decode("0a71d5cf99849bc13d73832dcd864244").unwrap();
        let data_1 = hex::decode("17f1ee0c6767a1f3f04bb3c1b7a4e0d4f0e59e5963c1a3bf1540a76b25136baef425faf488722e3e331c77d26fbbd8300df532498f50c5ecd243f481f09348f964ddb8056f6e2886bb5b2f453fcf1de5629f3d166324570bf849792d35e3f711b041b1a7e30494b5d1316484ed85b8da37094627a8e66003d079bf").unwrap();
        let data_2 = hex::decode("d8beaa80dc").unwrap();
        let expected = "2a0f542090b51b84465cd93e5ddeeaa14ca51162f48047835d2df845fb488af4";

        test_generic_state_multiple_append(
            HmacSha256State::new(&p_key).unwrap(),
            &data_1,
            &data_2,
            expected,
        );
    }

    #[test]
    pub fn test_stateless_hmac_sha256() {
        let p_key = hex::decode("0a71d5cf99849bc13d73832dcd864244").unwrap();
        let data = hex::decode("17f1ee0c6767a1f3f04bb3c1b7a4e0d4f0e59e5963c1a3bf1540a76b25136baef425faf488722e3e331c77d26fbbd8300df532498f50c5ecd243f481f09348f964ddb8056f6e2886bb5b2f453fcf1de5629f3d166324570bf849792d35e3f711b041b1a7e30494b5d1316484ed85b8da37094627a8e66003d079bfd8beaa80dc").unwrap();
        let expected = "2a0f542090b51b84465cd93e5ddeeaa14ca51162f48047835d2df845fb488af4";
        let mut result: [u8; SHA256_HMAC_RESULT_SIZE] = [0; SHA256_HMAC_RESULT_SIZE];

        hmac_sha256(&p_key, &data, &mut result).unwrap();
        assert_eq!(hex::encode(result), expected);
    }

    #[test]
    pub fn test_hmac_sha384() {
        let p_key = hex::decode("ba139c3403432b6ee435d71fed08d6fa12aee12201f02d47b3b29d12417936c4")
            .unwrap();
        let data = hex::decode("beec952d19e8b3db3a4b7fdb4c1d2ea1c492741ea23ceb92f380b9a29b476eaa51f52b54eb9f096adc79b8e8fb8d675686b3e45466bd0577b4f246537dbeb3d9c2a709e4c383180e7ee86bc872e52baaa8ef4107f41ebbc5799a716b6b50e87c19e976042afca7702682e0a2398b42453430d15ed5c9d62448608212ed65d33a").unwrap();
        let expected = "864c0a933ee2fe540e4444399add1cd94ff6e4e14248eaf6df7127cd12c7a9e0f7bd92b303715c06d1c6481114d22167";

        let hmac_test = HmacSha384State::new(&p_key).unwrap();
        test_generic_hmac_state(hmac_test, &data, expected);
    }

    #[test]
    pub fn test_hmac_sha384_state_copy() {
        let p_key = hex::decode("ba139c3403432b6ee435d71fed08d6fa12aee12201f02d47b3b29d12417936c4")
            .unwrap();
        let data = hex::decode("beec952d19e8b3db3a4b7fdb4c1d2ea1c492741ea23ceb92f380b9a29b476eaa51f52b54eb9f096adc79b8e8fb8d675686b3e45466bd0577b4f246537dbeb3d9c2a709e4c383180e7ee86bc872e52baaa8ef4107f41ebbc5799a716b6b50e87c19e976042afca7702682e0a2398b42453430d15ed5c9d62448608212ed65d33a").unwrap();

        let hmac_state = HmacSha384State::new(&p_key).unwrap();
        test_generic_state_copy(hmac_state, &data);
    }

    #[test]
    fn test_hmac_sha384_multiple_append() {
        let p_key = hex::decode("ba139c3403432b6ee435d71fed08d6fa12aee12201f02d47b3b29d12417936c4")
            .unwrap();
        let data_1 = hex::decode("beec952d19e8b3db3a4b7fdb4c1d2ea1c492741ea23ceb92f380b9a29b476eaa51f52b54eb9f096adc79b8e8fb8d675686b3e45466bd0577b4f246537dbeb3d9c2a709e4c383180e7ee86bc872e52baaa8ef4107f41ebbc5799a716b6b50e87c19e976042afca7702682e0a2398b42453430d15ed5c9d62448608212").unwrap();
        let data_2 = hex::decode("ed65d33a").unwrap();
        let expected = "864c0a933ee2fe540e4444399add1cd94ff6e4e14248eaf6df7127cd12c7a9e0f7bd92b303715c06d1c6481114d22167";

        test_generic_state_multiple_append(
            HmacSha384State::new(&p_key).unwrap(),
            &data_1,
            &data_2,
            expected,
        );
    }

    #[test]
    pub fn test_stateless_hmac384() {
        let p_key = hex::decode("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b").unwrap();
        let data = hex::decode("").unwrap();
        let expected = "ad88735f29e167dabded11b57e168f0b773b2985f4c2d2234c8d7a6bf01e2a791590bc0165003f9a7e47c4c687622fd6";
        let mut result: [u8; SHA384_HMAC_RESULT_SIZE] = [0; SHA384_HMAC_RESULT_SIZE];

        hmac_sha384(&p_key, &data, &mut result).unwrap();
        assert_eq!(hex::encode(result), expected);
    }
}
