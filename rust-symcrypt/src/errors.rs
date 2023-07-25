use std::convert::From;
use symcrypt_sys;

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
            0 => SymCryptError::NoError,
            32768 => SymCryptError::Unused,
            32769 => SymCryptError::WrongKeySize,
            32770 => SymCryptError::WrongBlockSize,
            32771 => SymCryptError::WrongDataSize,
            32772 => SymCryptError::WrongNonceSize,
            32773 => SymCryptError::WrongTagSize,
            32774 => SymCryptError::WrongIterationCount,
            32775 => SymCryptError::AuthenticationFailure,
            32776 => SymCryptError::ExternalFailure,
            32777 => SymCryptError::FipsFailure,
            32778 => SymCryptError::HardwareFailure,
            32779 => SymCryptError::NotImplemented,
            32780 => SymCryptError::InvalidBlob,
            32781 => SymCryptError::BufferTooSmall,
            32782 => SymCryptError::InvalidArgument,
            32783 => SymCryptError::MemoryAllocationFailure,
            32784 => SymCryptError::SignatureVerificationFailure,
            32785 => SymCryptError::IncompatibleFormat,
            32786 => SymCryptError::ValueTooLarge,
            32787 => SymCryptError::SessionReplayFailure,
            _ => SymCryptError::UnknownError(err),
        }
    }
}
