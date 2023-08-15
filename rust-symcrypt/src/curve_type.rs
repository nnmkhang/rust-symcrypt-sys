/* Friendly rust types for CurveTypes. */

//use lazy_static::lazy_static;
use symcrypt_sys;

#[derive(Copy, Clone, PartialEq)]
pub enum CurveType {
    NistP256,
    NistP384,
    Curve25519,
}

pub(crate) fn convert_curve(curve: CurveType) -> symcrypt_sys::PCSYMCRYPT_ECURVE_PARAMS {
    match curve {
        CurveType::NistP256 => unsafe { symcrypt_sys::SymCryptEcurveParamsNistP256 }, // SAFETY: FFI calls
        CurveType::NistP384 => unsafe { symcrypt_sys::SymCryptEcurveParamsNistP384 }, // SAFETY: FFI calls
        CurveType::Curve25519 => unsafe { symcrypt_sys::SymCryptEcurveParamsCurve25519 }, // SAFETY: FFI calls
    }
}

// TODO: implement lazy static for curve allocations.

// pub(crate) fn convert_curve(curve: CurveType) -> symcrypt_sys::PCSYMCRYPT_ECURVE_PARAMS {
//     match curve {
//         CurveType::NistP256 => *NIST_P256_CURVE_PARAMS,
//         CurveType::Nistp384 => *NIST_P384_CURVE_PARAMS,
//         CurveType::Curve25519 => *CURVE_25519_PARAMS,
//     }
// }

// lazy_static! {
//     static ref NIST_P256_CURVE_PARAMS: symcrypt_sys::PCSYMCRYPT_ECURVE_PARAMS = {
//         // SAFETY: FFI call, assuming SymCryptEcurveParamsNistP256 is a valid pointer
//         unsafe { &symcrypt_sys::SymCryptEcurveParamsNistP256 }
//     };

//     static ref NIST_P384_CURVE_PARAMS: symcrypt_sys::PCSYMCRYPT_ECURVE_PARAMS = {
//         // SAFETY: FFI call, assuming SymCryptEcurveParamsNistP384 is a valid pointer
//         unsafe { &symcrypt_sys::SymCryptEcurveParamsNistP384 }
//     };

//     static ref CURVE_25519_PARAMS: symcrypt_sys::PCSYMCRYPT_ECURVE_PARAMS = {
//         // SAFETY: FFI call, assuming SymCryptEcurveParamsCurve25519 is a valid pointer
//         unsafe { &symcrypt_sys::SymCryptEcurveParamsCurve25519 }
//     };
// }
