use core::ffi::c_void;
use std::mem;
use std::ptr;
use symcrypt_sys;

pub const SHA256_HMAC_RESULT_SIZE: usize = symcrypt_sys::SYMCRYPT_SHA256_RESULT_SIZE as usize;
pub const SHA384_HMAC_RESULT_SIZE: usize = symcrypt_sys::SYMCRYPT_SHA384_RESULT_SIZE as usize;

pub struct HmacSha256State {
    state: symcrypt_sys::SYMCRYPT_HMAC_SHA256_STATE,
    expanded_key: symcrypt_sys::SYMCRYPT_HMAC_SHA256_EXPANDED_KEY,
}

impl HmacSha256State {
    pub fn new(key: &[u8]) -> Self {
        let mut instance = HmacSha256State {
            state: symcrypt_sys::SYMCRYPT_HMAC_SHA256_STATE::default(),
            expanded_key: symcrypt_sys::SYMCRYPT_HMAC_SHA256_EXPANDED_KEY::default(),
        };
        unsafe {
            symcrypt_sys::SymCryptHmacSha256ExpandKey(
                &mut instance.expanded_key,
                key.as_ptr(),
                key.len() as symcrypt_sys::SIZE_T,
            );
            symcrypt_sys::SymCryptHmacSha256Init(&mut instance.state, &instance.expanded_key);
        }
        instance
    }

    pub fn append(&mut self, data: &[u8]) {
        unsafe {
            symcrypt_sys::SymCryptHmacSha256Append(
                &mut self.state,
                data.as_ptr(),
                data.len() as symcrypt_sys::SIZE_T,
            )
        }
    }

    pub fn result(&mut self, result: &mut [u8; SHA256_HMAC_RESULT_SIZE]) {
        unsafe {
            symcrypt_sys::SymCryptHmacSha256Result(&mut self.state, result.as_mut_ptr());
        }
    }
}

impl Drop for HmacSha256State {
    fn drop(&mut self) {
        unsafe {
            symcrypt_sys::SymCryptWipe(
                ptr::addr_of_mut!(self.state) as *mut c_void,
                mem::size_of_val(&mut self.state) as symcrypt_sys::SIZE_T,
            );

            symcrypt_sys::SymCryptWipe(
                ptr::addr_of_mut!(self.expanded_key) as *mut c_void,
                mem::size_of_val(&mut self.expanded_key) as symcrypt_sys::SIZE_T,
            );
        }
    }
}

pub fn hmac_sha256(key: &[u8], data: &[u8], result: &mut [u8; SHA256_HMAC_RESULT_SIZE]) {
    unsafe {
        let mut expanded_key = symcrypt_sys::SYMCRYPT_HMAC_SHA256_EXPANDED_KEY::default();
        symcrypt_sys::SymCryptHmacSha256ExpandKey(
            &mut expanded_key,
            key.as_ptr(),
            key.len() as symcrypt_sys::SIZE_T,
        );
        symcrypt_sys::SymCryptHmacSha256(
            &mut expanded_key,
            data.as_ptr(),
            data.len() as symcrypt_sys::SIZE_T,
            result.as_mut_ptr(),
        );
        symcrypt_sys::SymCryptWipe(
            ptr::addr_of_mut!(expanded_key) as *mut c_void,
            mem::size_of_val(&mut expanded_key) as symcrypt_sys::SIZE_T,
        );
    }
}

pub struct HmacSha384State {
    state: symcrypt_sys::SYMCRYPT_HMAC_SHA384_STATE,
    expanded_key: symcrypt_sys::SYMCRYPT_HMAC_SHA384_EXPANDED_KEY,
}

impl HmacSha384State {
    pub fn new(key: &[u8]) -> Self {
        let mut instance = HmacSha384State {
            state: symcrypt_sys::SYMCRYPT_HMAC_SHA384_STATE::default(),
            expanded_key: symcrypt_sys::SYMCRYPT_HMAC_SHA384_EXPANDED_KEY::default(),
        };
        unsafe {
            symcrypt_sys::SymCryptHmacSha384ExpandKey(
                &mut instance.expanded_key,
                key.as_ptr(),
                key.len() as symcrypt_sys::SIZE_T,
            );
            symcrypt_sys::SymCryptHmacSha384Init(&mut instance.state, &instance.expanded_key);
        }
        instance
    }

    pub fn append(&mut self, data: &[u8]) {
        unsafe {
            symcrypt_sys::SymCryptHmacSha384Append(
                &mut self.state,
                data.as_ptr(),
                data.len() as symcrypt_sys::SIZE_T,
            )
        }
    }

    pub fn result(&mut self, result: &mut [u8; SHA384_HMAC_RESULT_SIZE]) {
        unsafe {
            symcrypt_sys::SymCryptHmacSha384Result(&mut self.state, result.as_mut_ptr());
        }
    }
}

impl Drop for HmacSha384State {
    fn drop(&mut self) {
        unsafe {
            symcrypt_sys::SymCryptWipe(
                ptr::addr_of_mut!(self.state) as *mut c_void,
                mem::size_of_val(&mut self.state) as symcrypt_sys::SIZE_T,
            );

            symcrypt_sys::SymCryptWipe(
                ptr::addr_of_mut!(self.expanded_key) as *mut c_void,
                mem::size_of_val(&mut self.expanded_key) as symcrypt_sys::SIZE_T,
            );
        }
    }
}

pub fn hmac_sha384(key: &[u8], data: &[u8], result: &mut [u8; SHA384_HMAC_RESULT_SIZE]) {
    unsafe {
        let mut expanded_key = symcrypt_sys::SYMCRYPT_HMAC_SHA384_EXPANDED_KEY::default();
        symcrypt_sys::SymCryptHmacSha384ExpandKey(
            &mut expanded_key,
            key.as_ptr(),
            key.len() as symcrypt_sys::SIZE_T,
        );

        symcrypt_sys::SymCryptHmacSha384(
            &mut expanded_key,
            data.as_ptr(),
            data.len() as symcrypt_sys::SIZE_T,
            result.as_mut_ptr(),
        );

        symcrypt_sys::SymCryptWipe(
            ptr::addr_of_mut!(expanded_key) as *mut c_void,
            mem::size_of_val(&mut expanded_key) as symcrypt_sys::SIZE_T,
        );
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    pub fn test_hmac_sha256() {
        let p_key = hex::decode("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b").unwrap();
        let data = hex::decode("").unwrap();
        let expected = "915cb2c078aaf5dfb3560cf6d96997e987b2de5cd46f9a2ef92493bfc34bab16";
        let mut result: [u8; SHA256_HMAC_RESULT_SIZE] = [0; SHA256_HMAC_RESULT_SIZE];

        let mut hmac_test = HmacSha256State::new(&p_key);
        hmac_test.append(&data);
        hmac_test.result(&mut result);
        assert_eq!(hex::encode(result), expected);
    }

    #[test]
    pub fn test_stateless_hmac_sha256() {
        let p_key = hex::decode("0a71d5cf99849bc13d73832dcd864244").unwrap();
        let data = hex::decode("17f1ee0c6767a1f3f04bb3c1b7a4e0d4f0e59e5963c1a3bf1540a76b25136baef425faf488722e3e331c77d26fbbd8300df532498f50c5ecd243f481f09348f964ddb8056f6e2886bb5b2f453fcf1de5629f3d166324570bf849792d35e3f711b041b1a7e30494b5d1316484ed85b8da37094627a8e66003d079bfd8beaa80dc").unwrap();
        let expected = "2a0f542090b51b84465cd93e5ddeeaa14ca51162f48047835d2df845fb488af4";
        let mut result: [u8; SHA256_HMAC_RESULT_SIZE] = [0; SHA256_HMAC_RESULT_SIZE];

        hmac_sha256(&p_key, &data, &mut result);
        assert_eq!(hex::encode(result), expected);
    }

    #[test]
    pub fn test_hmac_sha384() {
        let p_key = hex::decode("ba139c3403432b6ee435d71fed08d6fa12aee12201f02d47b3b29d12417936c4")
            .unwrap();
        let data = hex::decode("beec952d19e8b3db3a4b7fdb4c1d2ea1c492741ea23ceb92f380b9a29b476eaa51f52b54eb9f096adc79b8e8fb8d675686b3e45466bd0577b4f246537dbeb3d9c2a709e4c383180e7ee86bc872e52baaa8ef4107f41ebbc5799a716b6b50e87c19e976042afca7702682e0a2398b42453430d15ed5c9d62448608212ed65d33a").unwrap();
        let expected = "864c0a933ee2fe540e4444399add1cd94ff6e4e14248eaf6df7127cd12c7a9e0f7bd92b303715c06d1c6481114d22167";
        let mut result: [u8; SHA384_HMAC_RESULT_SIZE] = [0; SHA384_HMAC_RESULT_SIZE];

        let mut hmac_test = HmacSha384State::new(&p_key);
        hmac_test.append(&data);
        hmac_test.result(&mut result);
        assert_eq!(hex::encode(result), expected);
    }

    #[test]
    pub fn test_stateless_hmac384() {
        let p_key = hex::decode("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b").unwrap();
        let data = hex::decode("").unwrap();
        let expected = "ad88735f29e167dabded11b57e168f0b773b2985f4c2d2234c8d7a6bf01e2a791590bc0165003f9a7e47c4c687622fd6";
        let mut result: [u8; SHA384_HMAC_RESULT_SIZE] = [0; SHA384_HMAC_RESULT_SIZE];

        hmac_sha384(&p_key, &data, &mut result);
        assert_eq!(hex::encode(result), expected);
    }
}
