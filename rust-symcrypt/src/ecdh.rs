//! EcDh functions. For further documentation please refer to symcrypt.h

use crate::eckey::*;
use crate::errors::SymCryptError;
use std::vec;
use symcrypt_sys;

/// Wrapper for the EcDh secret agreement result value. This is in place to make the return clear to the caller.
#[derive(Debug)]
pub struct EcDhSecretAgreement(Vec<u8>);

impl EcDhSecretAgreement {
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

/// EcDh struct holds the EcKey as well as the associated CurveType
///
/// [`EcKey`] holds the public/private key pair that is associated with the provided CurveType.
/// EcKey is owned by EcDh struct, and will drop when EcDh leaves scope.
pub struct EcDh {
    curve_type: CurveType,
    key: EcKey,
}

/// Impl for EcDh struct.
/// The EcDh object is
///
/// [`new()`] takes in a curve and returns an EcDh struct who's EcKey has a private/public key pair assigned to it.
///
/// ['from_public_key_bytes()'] takes in a public_key and creates a EcDh struct who's EcKey has only a public key attached.
///
/// [`get_public_key_bytes()`] returns a Vec<u8> that is the public key associated with the current EcKey
///  
/// [`ecdh_secret_agreement()`] takes in two EcDh structs and returns the associated secret agreement.
impl EcDh {
    pub fn new(curve: CurveType) -> Result<Self, SymCryptError> {
        let ecdh_key = EcKey::new(curve)?;
        unsafe {
            // SAFETY: FFI calls
            match symcrypt_sys::SymCryptEckeySetRandom(
                symcrypt_sys::SYMCRYPT_FLAG_ECKEY_ECDH,
                ecdh_key.inner(),
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

    pub fn from_public_key_bytes(
        curve: CurveType,
        public_key: &[u8],
    ) -> Result<Self, SymCryptError> {
        let num_format = get_num_format(curve);
        let ec_point_format = symcrypt_sys::_SYMCRYPT_ECPOINT_FORMAT_SYMCRYPT_ECPOINT_FORMAT_XY;
        let edch_key = EcKey::new(curve)?;

        unsafe {
            // SAFETY: FFI calls
            match symcrypt_sys::SymCryptEckeySetValue(
                std::ptr::null(), // private key set to null since none is generated
                0,
                public_key.as_ptr(),
                public_key.len() as symcrypt_sys::SIZE_T,
                num_format,
                ec_point_format,
                symcrypt_sys::SYMCRYPT_FLAG_ECKEY_ECDH,
                edch_key.inner(),
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

    pub fn get_public_key_bytes(&self) -> Result<Vec<u8>, SymCryptError> {
        let num_format = get_num_format(self.curve_type);
        let ec_point_format = symcrypt_sys::_SYMCRYPT_ECPOINT_FORMAT_SYMCRYPT_ECPOINT_FORMAT_XY;

        unsafe {
            // SAFETY: FFI calls
            let pub_key_len = symcrypt_sys::SymCryptEckeySizeofPublicKey(
                self.key.inner(),
                symcrypt_sys::_SYMCRYPT_ECPOINT_FORMAT_SYMCRYPT_ECPOINT_FORMAT_XY,
            );

            let mut pub_key_bytes = vec![0u8; pub_key_len as usize];

            match symcrypt_sys::SymCryptEckeyGetValue(
                self.key.inner(),
                std::ptr::null_mut(), // setting private key to null since we will only access public key
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
        let secret_length = private.key.curve().get_size();
        let mut secret = vec![0u8; secret_length as usize];

        unsafe {
            // SAFETY: FFI calls
            match symcrypt_sys::SymCryptEcDhSecretAgreement(
                private.key.inner(),
                public.key.inner(),
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
        let ecdh_1_private = EcDh::new(CurveType::NistP256).unwrap();
        let ecdh_2_private = EcDh::new(CurveType::NistP256).unwrap();

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

        assert_eq!(secret_agreement_1.as_bytes(), secret_agreement_2.as_bytes());
    }

    #[test]
    fn test_ecdh_nist_p384() {
        symcrypt_init(); // must run symcrypt_init for the alloc callbacks to initialize
        let ecdh_1_private = EcDh::new(CurveType::NistP384).unwrap();
        let ecdh_2_private = EcDh::new(CurveType::NistP384).unwrap();

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

        assert_eq!(secret_agreement_1.as_bytes(), secret_agreement_2.as_bytes());
    }

    #[test]
    fn test_ecdh_curve_25519() {
        symcrypt_init(); // must run symcrypt_init for the alloc callbacks to initialize
        let ecdh_1_private = EcDh::new(CurveType::Curve25519).unwrap();
        let ecdh_2_private = EcDh::new(CurveType::Curve25519).unwrap();

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

        assert_eq!(secret_agreement_1.as_bytes(), secret_agreement_2.as_bytes());
    }

    #[test]
    fn test_ecdh_failure() {
        symcrypt_init(); // must run symcrypt_init for the alloc callbacks to initialize
        let ecdh_1_private = EcDh::new(CurveType::NistP384).unwrap();
        let ecdh_2_private = EcDh::new(CurveType::NistP256).unwrap();

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
