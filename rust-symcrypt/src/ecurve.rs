//! Friendly rust types for CurveTypes.

//use lazy_static::lazy_static;
use crate::errors::SymCryptError;
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

pub(crate) fn get_num_format(curve_type: CurveType) -> i32 {
    if curve_type == CurveType::Curve25519 {
        return symcrypt_sys::_SYMCRYPT_NUMBER_FORMAT_SYMCRYPT_NUMBER_FORMAT_LSB_FIRST;
    } else {
        return symcrypt_sys::_SYMCRYPT_NUMBER_FORMAT_SYMCRYPT_NUMBER_FORMAT_MSB_FIRST;
    };
}

pub(crate) struct EcCurve(pub(crate) symcrypt_sys::PSYMCRYPT_ECURVE);

impl EcCurve {
    pub(crate) fn new(curve: CurveType) -> Result<Self, SymCryptError> {
        unsafe {
            let curve_ptr = symcrypt_sys::SymCryptEcurveAllocate(convert_curve(curve), 0);
            if curve_ptr.is_null() {
                return Err(SymCryptError::MemoryAllocationFailure);
            }
            // curve needs to be wrapped to properly free the curve in the case there is an error in future initialization in EcDsa or EcDh
            Ok(EcCurve(curve_ptr))
        }
    }
}

impl Drop for EcCurve {
    fn drop(&mut self) {
        unsafe { symcrypt_sys::SymCryptEcurveFree(self.0) }
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
