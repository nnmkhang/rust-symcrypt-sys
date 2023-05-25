#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
#![allow(clippy::all)]

extern crate libc;

mod symcrypt_bindings;
pub use symcrypt_bindings::*;

// impl Default for _SYMCRYPT_SHA256_STATE {
//     fn default() -> _SYMCRYPT_SHA256_STATE {
//         let state = _SYMCRYPT_SHA256_STATE {
//                 bytesInBuffer: 0,
//                 magic: 0,
//                 dataLengthL: 0,
//                 dataLengthH: 0,
//                 buffer: [0u8; 64usize],
//                 chain: _SYMCRYPT_SHA256_CHAINING_STATE {
//                     H: [0u32; 8usize],
//                 },
//         };
//         state
//     }
    
// }
