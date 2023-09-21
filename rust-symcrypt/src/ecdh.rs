//! EcDh functions. For further documentation please refer to symcrypt.h 

use crate::ecurve::*;
use crate::errors::SymCryptError;
use std::vec;
use symcrypt_sys;

/// EcDhKey is a wrapper around symcrypt_sys::PSYMCRYPT_ECKEY, this is to let rust handle the free'ing of this pointer
/// EcDhKey must be allocated after EcDhCurve and free'd before EcDhCurve is free'd
pub struct EcDhKey {
    inner: symcrypt_sys::PSYMCRYPT_ECKEY,
    curve: EcCurve,
}

#[derive(Debug)]
pub struct EcDhSecretAgreement(pub Vec<u8>);

impl EcDhKey {
    pub fn new(curve: CurveType) -> Result<Self, SymCryptError> {
        unsafe {
            // Allocating curve needed for key derivation. This pointer must be dropped after the key is dropped.
            let ecdh_curve = EcCurve::new(curve)?;

            // Key must be dropped before curve is dropped
            let key_ptr = symcrypt_sys::SymCryptEckeyAllocate(ecdh_curve.0);
            if key_ptr.is_null() {
                return Err(SymCryptError::MemoryAllocationFailure);
            }
            let key = EcDhKey {
                inner: key_ptr,
                curve: ecdh_curve,
            };
            Ok(key)
        }
    }
}

/// Must drop the Key before the expanded curve is dropped.
impl Drop for EcDhKey {
    fn drop(&mut self) {
        unsafe {
            symcrypt_sys::SymCryptEckeyFree(self.inner);
        }
    }
}

/// EcDhKey's ownership is passed to EcDh struct, and will drop when EcDh leaves scope.
pub struct EcDh {
    curve_type: CurveType,
    key: EcDhKey,
}

impl EcDh {
    /// EcDh::new() returns an EcDh struct that has a private/public key pair.
    pub fn new(curve: CurveType) -> Result<Self, SymCryptError> {
        unsafe {
            // SAFETY: FFI calls

            let ecdh_key = EcDhKey::new(curve)?;

            match symcrypt_sys::SymCryptEckeySetRandom(
                symcrypt_sys::SYMCRYPT_FLAG_ECKEY_ECDH,
                ecdh_key.inner,
            ) {
                symcrypt_sys::SYMCRYPT_ERROR_SYMCRYPT_NO_ERROR => {
                    let instance = EcDh {
                        curve_type: curve,
                        key: ecdh_key,
                    };
                    Ok(instance)
                }
                err => Err(err.into()),
            }
        }
    }

    /// EcDh::from_public_key_bytes() returns an EcDh struct that only has a public key attached.
    pub fn from_public_key_bytes(
        curve: CurveType,
        public_key: &[u8],
    ) -> Result<Self, SymCryptError> {
        let num_format = get_num_format(curve);

        let ec_point_format = symcrypt_sys::_SYMCRYPT_ECPOINT_FORMAT_SYMCRYPT_ECPOINT_FORMAT_XY;

        let edch_key = EcDhKey::new(curve)?;

        unsafe {
            // SAFETY: FFI calls
            match symcrypt_sys::SymCryptEckeySetValue(
                std::ptr::null(),
                0,
                public_key.as_ptr(),
                public_key.len() as symcrypt_sys::SIZE_T,
                num_format,
                ec_point_format,
                symcrypt_sys::SYMCRYPT_FLAG_ECKEY_ECDH,
                edch_key.inner,
            ) {
                symcrypt_sys::SYMCRYPT_ERROR_SYMCRYPT_NO_ERROR => {
                    let instance = EcDh {
                        curve_type: curve,
                        key: edch_key,
                    };
                    Ok(instance)
                }
                err => Err(err.into()),
            }
        }
    }

    pub fn get_public_key_bytes(&mut self) -> Result<Vec<u8>, SymCryptError> {
        let num_format = get_num_format(self.curve_type);
        let ec_point_format = symcrypt_sys::_SYMCRYPT_ECPOINT_FORMAT_SYMCRYPT_ECPOINT_FORMAT_XY;

        unsafe {
            // SAFETY: FFI calls
            let pub_key_len = symcrypt_sys::SymCryptEckeySizeofPublicKey(
                self.key.inner,
                symcrypt_sys::_SYMCRYPT_ECPOINT_FORMAT_SYMCRYPT_ECPOINT_FORMAT_XY,
            );

            let mut pub_key_bytes = vec![0u8; pub_key_len as usize];

            match symcrypt_sys::SymCryptEckeyGetValue(
                self.key.inner,
                std::ptr::null_mut(),
                0 as symcrypt_sys::SIZE_T,
                pub_key_bytes.as_mut_ptr(),
                pub_key_len as symcrypt_sys::SIZE_T,
                num_format,
                ec_point_format,
                0, // No flags allowed
            ) {
                symcrypt_sys::SYMCRYPT_ERROR_SYMCRYPT_NO_ERROR => Ok(pub_key_bytes),
                err => Err(err.into()),
            }
        }
    }

    pub fn ecdh_secret_agreement(
        private: &EcDh,
        public: &EcDh,
    ) -> Result<EcDhSecretAgreement, SymCryptError> {
        let num_format = get_num_format(private.curve_type);

        unsafe {
            // SAFETY: FFI calls
            let secret_length = symcrypt_sys::SymCryptEcurveSizeofFieldElement(private.key.curve.0);
            let mut secret = vec![0u8; secret_length as usize];

            match symcrypt_sys::SymCryptEcDhSecretAgreement(
                private.key.inner,
                public.key.inner,
                num_format,
                0,
                secret.as_mut_ptr(),
                secret.len() as symcrypt_sys::SIZE_T,
            ) {
                symcrypt_sys::SYMCRYPT_ERROR_SYMCRYPT_NO_ERROR => Ok(EcDhSecretAgreement(secret)),
                err => Err(err.into()),
            }
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::symcrypt_init;

    /// symcrypt_sys::SymCryptModuleInit() must be called via lib.rs in order to initialize the callbacks for
    /// SymCryptEcurveAllocate, SymCryptEckeyAllocate, SymCryptCallbackAlloc, etc.
    #[test]
    fn test_ecdh_nist_p256() {
        symcrypt_init(); // must run symcrypt_init for the alloc callbacks to initialize
        let mut ecdh_1_private = EcDh::new(CurveType::NistP256).unwrap();
        let mut ecdh_2_private = EcDh::new(CurveType::NistP256).unwrap();

        let public_bytes_1 = ecdh_1_private.get_public_key_bytes().unwrap();
        let public_bytes_2 = ecdh_2_private.get_public_key_bytes().unwrap();

        let ecdh_1_public =
            EcDh::from_public_key_bytes(CurveType::NistP256, &public_bytes_1.as_slice()).unwrap();
        let ecdh_2_public =
            EcDh::from_public_key_bytes(CurveType::NistP256, &public_bytes_2.as_slice()).unwrap();

        let secret_agreement_1 =
            EcDh::ecdh_secret_agreement(&ecdh_1_private, &ecdh_2_public).unwrap();
        let secret_agreement_2 =
            EcDh::ecdh_secret_agreement(&ecdh_2_private, &ecdh_1_public).unwrap();

        assert_eq!(secret_agreement_1.0, secret_agreement_2.0);
    }

    #[test]
    fn test_ecdh_nist_p384() {
        symcrypt_init(); // must run symcrypt_init for the alloc callbacks to initialize
        let mut ecdh_1_private = EcDh::new(CurveType::NistP384).unwrap();
        let mut ecdh_2_private = EcDh::new(CurveType::NistP384).unwrap();

        let public_bytes_1 = ecdh_1_private.get_public_key_bytes().unwrap();
        let public_bytes_2 = ecdh_2_private.get_public_key_bytes().unwrap();

        let ecdh_1_public =
            EcDh::from_public_key_bytes(CurveType::NistP384, &public_bytes_1.as_slice()).unwrap();
        let ecdh_2_public =
            EcDh::from_public_key_bytes(CurveType::NistP384, &public_bytes_2.as_slice()).unwrap();

        let secret_agreement_1 =
            EcDh::ecdh_secret_agreement(&ecdh_1_private, &ecdh_2_public).unwrap();
        let secret_agreement_2 =
            EcDh::ecdh_secret_agreement(&ecdh_2_private, &ecdh_1_public).unwrap();

        assert_eq!(secret_agreement_1.0, secret_agreement_2.0);
    }

    #[test]
    fn test_ecdh_curve_25519() {
        symcrypt_init(); // must run symcrypt_init for the alloc callbacks to initialize
        let mut ecdh_1_private = EcDh::new(CurveType::Curve25519).unwrap();
        let mut ecdh_2_private = EcDh::new(CurveType::Curve25519).unwrap();

        let public_bytes_1 = ecdh_1_private.get_public_key_bytes().unwrap();
        let public_bytes_2 = ecdh_2_private.get_public_key_bytes().unwrap();

        let ecdh_1_public =
            EcDh::from_public_key_bytes(CurveType::Curve25519, &public_bytes_1.as_slice()).unwrap();
        let ecdh_2_public =
            EcDh::from_public_key_bytes(CurveType::Curve25519, &public_bytes_2.as_slice()).unwrap();

        let secret_agreement_1 =
            EcDh::ecdh_secret_agreement(&ecdh_1_private, &ecdh_2_public).unwrap();
        let secret_agreement_2 =
            EcDh::ecdh_secret_agreement(&ecdh_2_private, &ecdh_1_public).unwrap();

        assert_eq!(secret_agreement_1.0, secret_agreement_2.0);
    }

    #[test]
    fn test_ecdh_failure() {
        symcrypt_init(); // must run symcrypt_init for the alloc callbacks to initialize
        let ecdh_1_private = EcDh::new(CurveType::NistP384).unwrap();
        let mut ecdh_2_private = EcDh::new(CurveType::NistP256).unwrap();

        let public_bytes_2 = ecdh_2_private.get_public_key_bytes().unwrap();

        let ecdh_2_public =
            EcDh::from_public_key_bytes(CurveType::NistP256, &public_bytes_2).unwrap();

        let secret_agreement_1 = EcDh::ecdh_secret_agreement(&ecdh_1_private, &ecdh_2_public);
        assert_eq!(
            secret_agreement_1.unwrap_err(),
            SymCryptError::InvalidArgument
        );
    }
}
