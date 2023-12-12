//! Friendly rust types for CurveTypes. please see symcrypt.h for more info

use crate::{errors::SymCryptError, symcrypt_init};
use lazy_static::lazy_static;
use symcrypt_sys;

/// [`CurveType`] provides an enum of the curve types that can be used when creating an [`EcKey`].
/// The current curve types supported is `NistP256`, `NistP384`, and `Curve25519`.
#[derive(Copy, Clone, PartialEq, Debug)]
pub enum CurveType {
    NistP256,
    NistP384,
    Curve25519,
}

/// [`EcKey`] is a wrapper around `symcrypt_sys::PSYMCRYPT_ECKEY`.
pub(crate) struct EcKey {
    // Allocation for EcKey is handled by SymCrypt via SymCryptEcKeyAllocate, and is subsequently stored on the stack, therefore pointer will
    // not move and Box<> is not needed.
    inner: symcrypt_sys::PSYMCRYPT_ECKEY,
    curve: &'static EcCurve,
}

/// [`EcCurve`] is a wrapper around `symcrypt_sys::PSYMCRYPT_ECURVE`.
pub(crate) struct EcCurve(pub(crate) symcrypt_sys::PSYMCRYPT_ECURVE);

/// Impl for [`EcKey`]
///
/// `new()` returns a new [`EcKey`] object that has the key and curve allocated.
///
/// `inner()` is an accessor to the inner field of the [`EcKey`] struct.
///
/// `curve()` is an accessor to the curve field of the EcKey struct.
impl EcKey {
    pub(crate) fn new(curve: CurveType) -> Result<Self, SymCryptError> {
        let ec_curve = &EcCurve::new(curve); // Can fail here due to insufficient memory.

        unsafe {
            // SAFETY: FFI calls
            // Stack allocated since we will do SymCryptEckeyAllocate.
            let key_ptr = symcrypt_sys::SymCryptEckeyAllocate(ec_curve.0);
            if key_ptr.is_null() {
                return Err(SymCryptError::MemoryAllocationFailure);
            }
            let key = EcKey {
                inner: key_ptr,
                curve: ec_curve,
            };
            Ok(key)
        }
    }

    // Reference is not needed here since we are working with a raw SymCrypt pointer.
    pub(crate) fn inner(&self) -> symcrypt_sys::PSYMCRYPT_ECKEY {
        self.inner
    }

    // Reference is used here since EcKey should still maintain ownership of the EcCurve.
    pub(crate) fn curve(&self) -> &EcCurve {
        &self.curve
    }
}

unsafe impl Send for EcKey {
    // TODO: Discuss send/sync for rustls
    // *const _SYMCRYPT_ECURVE_PARAMS cannot be shared between threads safely
    // the trait Sync is not implemented for *const _SYMCRYPT_ECURVE_PARAMS
}

unsafe impl Sync for EcKey {
    // TODO: Discuss send/sync for rustls
}

unsafe impl Send for EcCurve {
    // TODO: Discuss send/sync for rustls
    // *const _SYMCRYPT_ECURVE_PARAMS cannot be shared between threads safely
    // the trait Sync is not implemented for *const _SYMCRYPT_ECURVE_PARAMS
}

unsafe impl Sync for EcCurve {
    // TODO: Discuss send/sync for rustls
}

/// Must drop the [`EcKey`] before the expanded [`EcCurve`] is dropped
/// [`EcCurve`] has static lifetime so this will always be the case.
impl Drop for EcKey {
    fn drop(&mut self) {
        unsafe {
            // SAFETY: FFI calls
            symcrypt_sys::SymCryptEckeyFree(self.inner);
        }
    }
}

// Curves can be re-used across EcKey calls, creating static references to save on allocations and increase perf.
// unwraps used here since only way this could fail is via not enough memory.
lazy_static! {
    static ref NIST_P256: EcCurve = internal_new(CurveType::NistP256).unwrap();
    static ref NIST_P384: EcCurve = internal_new(CurveType::NistP384).unwrap();
    static ref CURVE_25519: EcCurve = internal_new(CurveType::Curve25519).unwrap();
}

// SymCryptInit must be called before any EcDh operations are performed.
fn internal_new(curve: CurveType) -> Result<EcCurve, SymCryptError> {
    unsafe {
        // SAFETY: FFI calls
        // Will only init once, subsequent calls to symcrypt_init() will be no-ops. Calling here incase user did
        // not call symcrypt_init() earlier on.
        symcrypt_init();

        // Stack allocated since will do SymCryptEcCurveAllocate.
        let curve_ptr = symcrypt_sys::SymCryptEcurveAllocate(convert_curve(curve), 0);
        if curve_ptr.is_null() {
            return Err(SymCryptError::MemoryAllocationFailure);
        }
        // Curve needs to be wrapped to properly free the curve in the case there is an error in future initialization in EcDsa or EcDh.
        Ok(EcCurve(curve_ptr))
    }
}

/// Impl for EcCurve
///
/// [`new()`] returns a [`EcCurve`] associated with the provided [`CurveType`].
///
/// [`get_size`] returns the size of the [`EcCurve`] as a u32.
impl EcCurve {
    pub(crate) fn new(curve: CurveType) -> &'static Self {
        let ec_curve: &'static EcCurve = match curve {
            CurveType::NistP256 => &*NIST_P256,
            CurveType::NistP384 => &*NIST_P384,
            CurveType::Curve25519 => &*CURVE_25519,
        };

        ec_curve
    }

    pub(crate) fn get_size(&self) -> u32 {
        unsafe {
            // SAFETY: FFI calls
            let curve_size = symcrypt_sys::SymCryptEcurveSizeofFieldElement(self.0);
            curve_size
        }
    }
}

/// Must drop [`EcCurve`] after [`EcKey`] is dropped.
impl Drop for EcCurve {
    fn drop(&mut self) {
        unsafe {
            // SAFETY: FFI calls
            symcrypt_sys::SymCryptEcurveFree(self.0)
        }
    }
}

/// convert_curve takes in the friendly CurveType enum and returns the symcrypt equivalent.
pub(crate) fn convert_curve(curve: CurveType) -> symcrypt_sys::PCSYMCRYPT_ECURVE_PARAMS {
    match curve {
        CurveType::NistP256 => unsafe { symcrypt_sys::SymCryptEcurveParamsNistP256 }, // SAFETY: FFI calls
        CurveType::NistP384 => unsafe { symcrypt_sys::SymCryptEcurveParamsNistP384 }, // SAFETY: FFI calls
        CurveType::Curve25519 => unsafe { symcrypt_sys::SymCryptEcurveParamsCurve25519 }, // SAFETY: FFI calls
    }
}

/// get_num_format returns the correct number format needed for TLS interop since 25519 spec defines the use of Little Endian.
pub(crate) fn get_num_format(curve_type: CurveType) -> i32 {
    if curve_type == CurveType::Curve25519 {
        return symcrypt_sys::_SYMCRYPT_NUMBER_FORMAT_SYMCRYPT_NUMBER_FORMAT_LSB_FIRST;
    } else {
        return symcrypt_sys::_SYMCRYPT_NUMBER_FORMAT_SYMCRYPT_NUMBER_FORMAT_MSB_FIRST;
    };
}
