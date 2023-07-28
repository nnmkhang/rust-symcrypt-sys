/* ChaChaPoly1305 Functions. For further documentation please refer to symcrypt.h */

use crate::errors::SymCryptError;
use std::vec;
use symcrypt_sys;

pub fn chacha20_poly1305_encrypt(
    key: &[u8; 32],   // ChaCha key length must be 32 bytes
    nonce: &[u8; 12], // ChaCha nonce length must be 12 bytes
    auth_data: Option<&[u8]>,
    plain_text: &[u8],
) -> Result<(Vec<u8>, [u8; 16]), SymCryptError> {
    let (auth_data_ptr, auth_data_len) = auth_data.map_or_else(
        || (std::ptr::null(), 0 as symcrypt_sys::SIZE_T),
        |data| (data.as_ptr(), data.len() as symcrypt_sys::SIZE_T),
    );

    let mut cipher_text = vec![0u8; plain_text.len()];
    let mut tag = [0u8; 16]; // ChaCha tag length must be 16 bytes

    unsafe {
        // SAFETY: FFI calls
        match symcrypt_sys::SymCryptChaCha20Poly1305Encrypt(
            key.as_ptr(),
            key.len() as symcrypt_sys::SIZE_T,
            nonce.as_ptr(),
            nonce.len() as symcrypt_sys::SIZE_T,
            auth_data_ptr,
            auth_data_len,
            plain_text.as_ptr(),
            cipher_text.as_mut_ptr(),
            cipher_text.len() as symcrypt_sys::SIZE_T,
            tag.as_mut_ptr(),
            tag.len() as symcrypt_sys::SIZE_T,
        ) {
            symcrypt_sys::SYMCRYPT_ERROR_SYMCRYPT_NO_ERROR => Ok((cipher_text, tag)),
            err => Err(err.into()),
        }
    }
}

pub fn chacha20_poly1305_decrypt(
    key: &[u8; 32],   // ChaCha key length must be 32 bytes
    nonce: &[u8; 12], // ChaCha nonce length must be 12 byte
    auth_data: Option<&[u8]>,
    cipher_text: &[u8],
    tag: &[u8; 16], // ChaCha tag length must be 16 bytes
) -> Result<Vec<u8>, SymCryptError> {
    let (auth_data_ptr, auth_data_len) = auth_data.map_or_else(
        || (std::ptr::null(), 0 as symcrypt_sys::SIZE_T),
        |data| (data.as_ptr(), data.len() as symcrypt_sys::SIZE_T),
    );

    let mut plain_text = vec![0u8; cipher_text.len()];

    unsafe {
        // SAFETY: FFI calls
        match symcrypt_sys::SymCryptChaCha20Poly1305Decrypt(
            key.as_ptr(),
            key.len() as symcrypt_sys::SIZE_T,
            nonce.as_ptr(),
            nonce.len() as symcrypt_sys::SIZE_T,
            auth_data_ptr,
            auth_data_len,
            cipher_text.as_ptr(),
            plain_text.as_mut_ptr(),
            plain_text.len() as symcrypt_sys::SIZE_T,
            tag.as_ptr(),
            tag.len() as symcrypt_sys::SIZE_T,
        ) {
            symcrypt_sys::SYMCRYPT_ERROR_SYMCRYPT_NO_ERROR => Ok(plain_text),
            err => Err(err.into()),
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_chacha_encrypt() {
        let key = hex::decode("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f")
            .unwrap();
        let nonce = hex::decode("070000004041424344454647").unwrap();
        let auth_data = hex::decode("50515253c0c1c2c3c4c5c6c7").unwrap();
        let pt = hex::decode("4c616469657320616e642047656e746c656d656e206f662074686520636c617373206f66202739393a204966204920636f756c64206f6666657220796f75206f6e6c79206f6e652074697020666f7220746865206675747572652c2073756e73637265656e20776f756c642062652069742e").unwrap();
        let ct = "d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d63dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b3692ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc3ff4def08e4b7a9de576d26586cec64b6116";
        let expected_tag = "1ae10b594f09e26a7e902ecbd0600691";

        let nonce_array: [u8; 12] = nonce.as_slice().try_into().unwrap();
        let key_array: [u8; 32] = key.as_slice().try_into().unwrap();

        let (result, tag) =
            chacha20_poly1305_encrypt(&key_array, &nonce_array, Some(&auth_data), &pt).unwrap();

        assert_eq!(hex::encode(result), ct);
        assert_eq!(hex::encode(tag), expected_tag);
    }

    #[test]
    fn test_chacha_decrypt() {
        let key = hex::decode("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f")
            .unwrap();
        let nonce = hex::decode("070000004041424344454647").unwrap();
        let auth_data = hex::decode("50515253c0c1c2c3c4c5c6c7").unwrap();
        let pt = "4c616469657320616e642047656e746c656d656e206f662074686520636c617373206f66202739393a204966204920636f756c64206f6666657220796f75206f6e6c79206f6e652074697020666f7220746865206675747572652c2073756e73637265656e20776f756c642062652069742e";
        let ct = hex::decode("d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d63dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b3692ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc3ff4def08e4b7a9de576d26586cec64b6116").unwrap();
        let tag = hex::decode("1ae10b594f09e26a7e902ecbd0600691").unwrap();
        let tag_array: [u8; 16] = tag.as_slice().try_into().unwrap();
        let nonce_array: [u8; 12] = nonce.as_slice().try_into().unwrap();
        let key_array: [u8; 32] = key.as_slice().try_into().unwrap();

        let result =
            chacha20_poly1305_decrypt(&key_array, &nonce_array, Some(&auth_data), &ct, &tag_array)
                .unwrap();

        assert_eq!(hex::encode(result), pt);
    }

    #[test]
    fn test_chacha_decrypt_failure() {
        let key = hex::decode("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f")
            .unwrap();
        let nonce = hex::decode("070000004041424344454648").unwrap();
        let auth_data = hex::decode("50515253c0c1c2c3c4c5c6c7").unwrap();
        let ct = hex::decode("d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d63dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b3692ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc3ff4def08e4b7a9de576d26586cec64b6116").unwrap();
        let tag = hex::decode("1ae10b594f09e26a7e902ecbd0600691").unwrap();

        let tag_array: [u8; 16] = tag.as_slice().try_into().unwrap();
        let nonce_array: [u8; 12] = nonce.as_slice().try_into().unwrap();
        let key_array: [u8; 32] = key.as_slice().try_into().unwrap();

        let result =
            chacha20_poly1305_decrypt(&key_array, &nonce_array, Some(&auth_data), &ct, &tag_array);

        assert_eq!(result.unwrap_err(), SymCryptError::AuthenticationFailure);
    }
}
