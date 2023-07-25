use std::convert::From;
use symcrypt_sys;

#[non_exhaustive]
#[derive(Debug, PartialEq)]
pub enum SymCryptError {
    NoError,
    Unused,
    WrongKeySize,
    WrongBlockSize,
    WrongDataSize,
    WrongNonceSize,
    WrongTagSize,
    WrongIterationCount,
    AuthenticationFailure,
    ExternalFailure,
    FipsFailure,
    HardwareFailure,
    NotImplemented,
    InvalidBlob,
    BufferTooSmall,
    InvalidArgument,
    MemoryAllocationFailure,
    SignatureVerificationFailure,
    IncompatibleFormat,
    ValueTooLarge,
    SessionReplayFailure,
    UnknownError(i32), // Catch-all for unknown error codes
}

impl From<symcrypt_sys::SYMCRYPT_ERROR> for SymCryptError {
    fn from(err: symcrypt_sys::SYMCRYPT_ERROR) -> Self {
        match err {
            symcrypt_sys::SYMCRYPT_ERROR_SYMCRYPT_NO_ERROR => SymCryptError::NoError,
            symcrypt_sys::SYMCRYPT_ERROR_SYMCRYPT_UNUSED => SymCryptError::Unused,
            symcrypt_sys::SYMCRYPT_ERROR_SYMCRYPT_WRONG_KEY_SIZE => SymCryptError::WrongKeySize,
            symcrypt_sys::SYMCRYPT_ERROR_SYMCRYPT_WRONG_BLOCK_SIZE => SymCryptError::WrongBlockSize,
            symcrypt_sys::SYMCRYPT_ERROR_SYMCRYPT_WRONG_DATA_SIZE => SymCryptError::WrongDataSize,
            symcrypt_sys::SYMCRYPT_ERROR_SYMCRYPT_WRONG_NONCE_SIZE => SymCryptError::WrongNonceSize,
            symcrypt_sys::SYMCRYPT_ERROR_SYMCRYPT_WRONG_TAG_SIZE => SymCryptError::WrongTagSize,
            symcrypt_sys::SYMCRYPT_ERROR_SYMCRYPT_WRONG_ITERATION_COUNT => SymCryptError::WrongIterationCount,
            symcrypt_sys::SYMCRYPT_ERROR_SYMCRYPT_AUTHENTICATION_FAILURE => SymCryptError::AuthenticationFailure,
            symcrypt_sys::SYMCRYPT_ERROR_SYMCRYPT_EXTERNAL_FAILURE => SymCryptError::ExternalFailure,
            symcrypt_sys::SYMCRYPT_ERROR_SYMCRYPT_FIPS_FAILURE => SymCryptError::FipsFailure,
            symcrypt_sys::SYMCRYPT_ERROR_SYMCRYPT_HARDWARE_FAILURE => SymCryptError::HardwareFailure,
            symcrypt_sys::SYMCRYPT_ERROR_SYMCRYPT_NOT_IMPLEMENTED => SymCryptError::NotImplemented,
            symcrypt_sys::SYMCRYPT_ERROR_SYMCRYPT_INVALID_BLOB => SymCryptError::InvalidBlob,
            symcrypt_sys::SYMCRYPT_ERROR_SYMCRYPT_BUFFER_TOO_SMALL => SymCryptError::BufferTooSmall,
            symcrypt_sys::SYMCRYPT_ERROR_SYMCRYPT_INVALID_ARGUMENT => SymCryptError::InvalidArgument,
            symcrypt_sys::SYMCRYPT_ERROR_SYMCRYPT_MEMORY_ALLOCATION_FAILURE => SymCryptError::MemoryAllocationFailure,
            symcrypt_sys::SYMCRYPT_ERROR_SYMCRYPT_SIGNATURE_VERIFICATION_FAILURE => SymCryptError::SignatureVerificationFailure,
            symcrypt_sys::SYMCRYPT_ERROR_SYMCRYPT_INCOMPATIBLE_FORMAT => SymCryptError::IncompatibleFormat,
            symcrypt_sys::SYMCRYPT_ERROR_SYMCRYPT_VALUE_TOO_LARGE => SymCryptError::ValueTooLarge,
            symcrypt_sys::SYMCRYPT_ERROR_SYMCRYPT_SESSION_REPLAY_FAILURE => SymCryptError::SessionReplayFailure,
            _ => SymCryptError::UnknownError(err),
        }
    }
}
