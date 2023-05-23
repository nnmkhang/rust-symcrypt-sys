use symcrypt_sys::*;

pub struct SymCryptInit;
impl SymCryptInit {
    pub fn new () {
        unsafe { 
            // symcrypt_sys::SymCryptInit(); 
            // TODO: Find out why SymCryptInit() breaks on linux / windows (BREAKING)
        }
    }
}

pub struct SymCryptSha256 {
    state: symcrypt_sys::_SYMCRYPT_SHA256_STATE
} 

impl SymCryptSha256 {
    pub fn new() -> Self {
        unsafe {
            let mut instance = SymCryptSha256 {
                state: symcrypt_sys::_SYMCRYPT_SHA256_STATE {
                    bytesInBuffer: 0,
                    magic: 0,
                    dataLengthL: 0,
                    dataLengthH: 0,
                    buffer: [0u8; 64],
                    chain: symcrypt_sys::_SYMCRYPT_SHA256_CHAINING_STATE {
                        H: [0u32; 8],
                    },
                }
            };
            symcrypt_sys::SymCryptSha256Init(&mut instance.state);
            instance
        }
    }

    pub fn sha256(data: &[u8], result: &mut [u8]) { // provide return vs modify 
        unsafe {
            symcrypt_sys::SymCryptSha256(
                data.as_ptr(), // pbData
                data.len() as symcrypt_sys::SIZE_T, //cbData
                result.as_mut_ptr() //pbResult
            );
        }
    }

    pub fn append(&mut self, data: &[u8] ) {
        unsafe {
            symcrypt_sys::SymCryptSha256Append(
                &mut self.state,
                data.as_ptr(), // pbData
                data.len() as symcrypt_sys::SIZE_T, //cbData
            );
        }
    }

    pub fn result(&mut self, result: &mut [u8]) {
        unsafe {
            symcrypt_sys::SymCryptSha256Result(&mut self.state, result.as_mut_ptr())
        }
    }

    pub fn drop(&mut self) {
        // TODO: figure out drop trait
    }
}

// extern "C" {
//     pub fn SymCryptSha256(pbData: PCBYTE, cbData: SIZE_T, pbResult: PBYTE);
// }
// extern "C" {
//     pub fn SymCryptSha256Init(pState: PSYMCRYPT_SHA256_STATE);
// }
// extern "C" {
//     pub fn SymCryptSha256Append(pState: PSYMCRYPT_SHA256_STATE, pbData: PCBYTE, cbData: SIZE_T);
// }
// extern "C" {
//     pub fn SymCryptSha256Result(pState: PSYMCRYPT_SHA256_STATE, pbResult: PBYTE);
// }
// extern "C" {
//     pub fn SymCryptSha256StateCopy(pSrc: PCSYMCRYPT_SHA256_STATE, pDst: PSYMCRYPT_SHA256_STATE);
// }
// extern "C" {
//     pub fn SymCryptSha256StateExport(pState: PCSYMCRYPT_SHA256_STATE, pbBlob: PBYTE);
// }
// extern "C" {
//     pub fn SymCryptSha256StateImport(
//         pState: PSYMCRYPT_SHA256_STATE,
//         pbBlob: PCBYTE,
//     ) -> SYMCRYPT_ERROR;
// }

// pub struct _SYMCRYPT_SHA256_STATE {
//     pub bytesInBuffer: UINT32,
//     pub magic: SIZE_T,
//     pub dataLengthL: UINT64,
//     pub dataLengthH: UINT64,
//     pub buffer: [BYTE; 64usize],
//     pub chain: SYMCRYPT_SHA256_CHAINING_STATE,
// }