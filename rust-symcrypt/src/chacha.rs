use std::vec;
use symcrypt_sys;

pub fn chacha20_poly1305_encrypt(
    key: &[u8],
    nonce: &[u8],
    auth_data: Option<&[u8]>,
    src: &[u8]
) -> Result<(Vec<u8>, Vec<u8>), symcrypt_sys::SYMCRYPT_ERROR> {

    let (auth_data_ptr, auth_data_len) = auth_data.map_or_else(
        || (std::ptr::null(), 0 as symcrypt_sys::SIZE_T),
        |data| (data.as_ptr(), data.len() as symcrypt_sys::SIZE_T),
    );

    let mut dst = vec![0u8; src.len()];
    let mut tag = vec![0u8; 16]; // for ChaCha tag size MUST be 16

    unsafe {
        match symcrypt_sys::SymCryptChaCha20Poly1305Encrypt(
            key.as_ptr(),
            key.len() as symcrypt_sys::SIZE_T,
            nonce.as_ptr(),
            nonce.len() as symcrypt_sys::SIZE_T,
            auth_data_ptr,
            auth_data_len,
            src.as_ptr(),
            dst.as_mut_ptr(),
            dst.len() as symcrypt_sys::SIZE_T,
            tag.as_mut_ptr(),
            tag.len() as symcrypt_sys::SIZE_T,
        ) {
            symcrypt_sys::SYMCRYPT_ERROR_SYMCRYPT_NO_ERROR => Ok((dst,tag)),
            err => Err(err)
        }
    }
}

pub fn chacha20_poly1305_decrypt(
    key: &[u8],
    nonce: &[u8],
    auth_data: Option<&[u8]>,
    src: &[u8],
    tag: &[u8; 16]
) -> Result<Vec<u8>, symcrypt_sys::SYMCRYPT_ERROR> {

    let (auth_data_ptr, auth_data_len) = auth_data.map_or_else(
        || (std::ptr::null(), 0 as symcrypt_sys::SIZE_T),
        |data| (data.as_ptr(), data.len() as symcrypt_sys::SIZE_T),
    );

    let mut dst = vec![0u8; src.len()];

    unsafe {
        match symcrypt_sys::SymCryptChaCha20Poly1305Decrypt( key.as_ptr(),
        key.len() as symcrypt_sys::SIZE_T,
        nonce.as_ptr(),
        nonce.len() as symcrypt_sys::SIZE_T,
        auth_data_ptr,
        auth_data_len,
        src.as_ptr(),
        dst.as_mut_ptr(),
        dst.len() as symcrypt_sys::SIZE_T,
        tag.as_ptr(),
        tag.len() as symcrypt_sys::SIZE_T)
        {
            symcrypt_sys::SYMCRYPT_ERROR_SYMCRYPT_NO_ERROR => Ok(dst),
            err => Err(err)
        }
    }
}

#[cfg(test)]
mod test {

    use super::*;

    #[test]
    fn test_chacha_encrypt() {
        let key = hex::decode("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f").unwrap();
        let nonce = hex::decode("070000004041424344454647").unwrap();
        let auth_data = hex::decode("50515253c0c1c2c3c4c5c6c7").unwrap();
        let pt = hex::decode("4c616469657320616e642047656e746c656d656e206f662074686520636c617373206f66202739393a204966204920636f756c64206f6666657220796f75206f6e6c79206f6e652074697020666f7220746865206675747572652c2073756e73637265656e20776f756c642062652069742e").unwrap();
        let ct = "d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d63dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b3692ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc3ff4def08e4b7a9de576d26586cec64b6116";
        let tag = "1ae10b594f09e26a7e902ecbd0600691";

        let (result,tag_result) = chacha20_poly1305_encrypt(&key, &nonce, Some(&auth_data), &pt).unwrap();

        assert_eq!(hex::encode(result), ct);
        assert_eq!(hex::encode(tag_result),tag);
    }

    #[test]
    fn test_chacha_decrypt() {
        let key = hex::decode("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f").unwrap();
        let nonce = hex::decode("070000004041424344454647").unwrap();
        let auth_data = hex::decode("50515253c0c1c2c3c4c5c6c7").unwrap();
        let pt = "4c616469657320616e642047656e746c656d656e206f662074686520636c617373206f66202739393a204966204920636f756c64206f6666657220796f75206f6e6c79206f6e652074697020666f7220746865206675747572652c2073756e73637265656e20776f756c642062652069742e";
        let ct = hex::decode("d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d63dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b3692ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc3ff4def08e4b7a9de576d26586cec64b6116").unwrap();
        let tag = hex::decode("1ae10b594f09e26a7e902ecbd0600691").unwrap();

        let result = chacha20_poly1305_decrypt(&key, &nonce, Some(&auth_data), &ct, &tag).unwrap();

        assert_eq!(hex::encode(result), pt);

    }
}
