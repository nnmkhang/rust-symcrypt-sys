/* Friendly rust types for MacAlgorithms. */

use symcrypt_sys;

pub enum MacAlgorithmType {
    HmacSha256,
    HmacSha384,
}

pub(crate) fn convert_mac(mac: MacAlgorithmType) -> symcrypt_sys::PCSYMCRYPT_MAC {
    match mac {
        MacAlgorithmType::HmacSha256 => unsafe { symcrypt_sys::SymCryptHmacSha256Algorithm }, // SAFETY: FFI calls
        MacAlgorithmType::HmacSha384 => unsafe { symcrypt_sys::SymCryptHmacSha384Algorithm }, // SAFETY: FFI calls
    }
}
