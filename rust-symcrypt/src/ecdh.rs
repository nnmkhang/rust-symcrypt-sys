/* EcDh functions. For further documentation please refer to symcrypt.h */

use crate::curve_type::*;
use crate::errors::SymCryptError;
use std::vec;
use symcrypt_sys;

pub struct EcDh {
    curve_type: CurveType,
    expanded_curve: Option<symcrypt_sys::PSYMCRYPT_ECURVE>,
    key: Option<symcrypt_sys::PSYMCRYPT_ECKEY>,
}

impl EcDh {
    /// EcDh::new() returns a EcDh struct that has a private/public key pair.
    pub fn new(curve: CurveType) -> Result<Self, SymCryptError> {
        let mut instance = EcDh {
            curve_type: curve,
            expanded_curve: None,
            key: None,
        };

        unsafe {
            // SAFETY: FFI calls
            let curve_ptr =
                symcrypt_sys::SymCryptEcurveAllocate(convert_curve(instance.curve_type), 0);
            if curve_ptr.is_null() {
                return Err(SymCryptError::MemoryAllocationFailure);
            }

            instance.expanded_curve = Some(curve_ptr);

            let key_ptr = symcrypt_sys::SymCryptEckeyAllocate(curve_ptr);
            if key_ptr.is_null() {
                return Err(SymCryptError::MemoryAllocationFailure);
            }

            instance.key = Some(key_ptr);

            match symcrypt_sys::SymCryptEckeySetRandom(
                symcrypt_sys::SYMCRYPT_FLAG_ECKEY_ECDH,
                instance.key.unwrap(),
            ) {
                symcrypt_sys::SYMCRYPT_ERROR_SYMCRYPT_NO_ERROR => {
                    Ok(instance)
                }
                err => Err(err.into()),
            }
        }
    }

    /// EcDh::from_public_key_bytes()    function returns a EcDh struct that only has a public key attached.
    pub fn from_public_key_bytes(
        curve: CurveType,
        public_key: &[u8],
    ) -> Result<Self, SymCryptError> {
        let mut instance = EcDh {
            curve_type: curve,
            expanded_curve: None,
            key: None,
        };

        let num_format = get_num_format(instance.curve_type);

        let ec_point_format = symcrypt_sys::_SYMCRYPT_ECPOINT_FORMAT_SYMCRYPT_ECPOINT_FORMAT_XY;

        unsafe {
            // SAFETY: FFI calls
            let curve_ptr =
                symcrypt_sys::SymCryptEcurveAllocate(convert_curve(instance.curve_type), 0);
            if curve_ptr.is_null() {
                return Err(SymCryptError::MemoryAllocationFailure);
            }

            instance.expanded_curve = Some(curve_ptr);

            let key_ptr = symcrypt_sys::SymCryptEckeyAllocate(instance.expanded_curve.unwrap());
            if key_ptr.is_null() {
                return Err(SymCryptError::InvalidArgument);
            }

            match symcrypt_sys::SymCryptEckeySetValue(
                std::ptr::null(),
                0,
                public_key.as_ptr(),
                public_key.len() as symcrypt_sys::SIZE_T,
                num_format,
                ec_point_format,
                symcrypt_sys::SYMCRYPT_FLAG_ECKEY_ECDH,
                key_ptr,
            ) {
                symcrypt_sys::SYMCRYPT_ERROR_SYMCRYPT_NO_ERROR => {
                    instance.key = Some(key_ptr);
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
                self.key.unwrap(),
                symcrypt_sys::_SYMCRYPT_ECPOINT_FORMAT_SYMCRYPT_ECPOINT_FORMAT_XY,
            );

            let mut pub_key_bytes = vec![0u8; pub_key_len as usize];

            match symcrypt_sys::SymCryptEckeyGetValue(
                self.key.unwrap(),
                std::ptr::null_mut(),
                0 as symcrypt_sys::SIZE_T,
                pub_key_bytes.as_mut_ptr(),
                pub_key_len as symcrypt_sys::SIZE_T,
                num_format,
                ec_point_format,
                0, // no flags allowed
            ) {
                symcrypt_sys::SYMCRYPT_ERROR_SYMCRYPT_NO_ERROR => Ok(pub_key_bytes),
                err => Err(err.into()),
            }
        }
    }

    pub fn ecdh_secret_agreement(private: &EcDh, public: &EcDh) -> Result<Vec<u8>, SymCryptError> {
        if private.curve_type != public.curve_type {
            return Err(SymCryptError::InvalidArgument);
        }

        let num_format = get_num_format(private.curve_type);

        unsafe {
            // SAFETY: FFI calls
            let secret_length =
                symcrypt_sys::SymCryptEcurveSizeofFieldElement(private.expanded_curve.unwrap());
            let mut secret = vec![0u8; secret_length as usize];

            match symcrypt_sys::SymCryptEcDhSecretAgreement(
                private.key.unwrap(),
                public.key.unwrap(),
                num_format,
                0,
                secret.as_mut_ptr(),
                secret.len() as symcrypt_sys::SIZE_T,
            ) {
                symcrypt_sys::SYMCRYPT_ERROR_SYMCRYPT_NO_ERROR => Ok(secret),
                err => Err(err.into()),
            }
        }
    }
}

impl Drop for EcDh {
    fn drop(&mut self) {
        unsafe {
            // SAFETY: FFI calls. Key depends on the expanded curve must be free'd first
            if let Some(key) = self.key {
                symcrypt_sys::SymCryptEckeyFree(key);
            }
            if let Some(expanded_curve) = self.expanded_curve {
                symcrypt_sys::SymCryptEcurveFree(expanded_curve);
            }
        }
    }
}

fn get_num_format(curve_type: CurveType)-> i32 {
    if curve_type == CurveType::Curve25519 {
        return symcrypt_sys::_SYMCRYPT_NUMBER_FORMAT_SYMCRYPT_NUMBER_FORMAT_LSB_FIRST;
    } else {
        return symcrypt_sys::_SYMCRYPT_NUMBER_FORMAT_SYMCRYPT_NUMBER_FORMAT_MSB_FIRST;
    };
}

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

        assert_eq!(secret_agreement_1, secret_agreement_2);
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

        assert_eq!(secret_agreement_1, secret_agreement_2);
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

        assert_eq!(secret_agreement_1, secret_agreement_2);
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
