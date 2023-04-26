use rust_symcrypt_sys::SymCrypt;

// pub mod ffi {
//     include!(concat!(env!("OUT_DIR"), "/bindings.rs"));
// }


// impl SymCrypt {
    
//     pub fn new () {
//         unsafe 
//         { 
//             // ffi::SymCryptInit();
//         }

//         //pub fn SymCryptModuleInit(api: UINT32, minor: UINT32);
//         // unsafe 
//         // {
//         //     ffi::SymCryptModuleInit();
//         // }
//     }

//     pub fn sha256(data: &[u8]) -> [u8; 32] {
//         let mut hash = [0u8; 32];
    
//         // Call the SymCrypt function using the generated bindings
//         unsafe {
//             println!("we're inside symcryptsha");
//             ffi::SymCryptSha256(
//                 data.as_ptr(), // pbData
//                 data.len() as u64, //cbData
//                 hash.as_mut_ptr(), //pbResult
//             );
//         }
//         hash
//     }
// }
fn main() {
    
    println!("Hello, world!");

    let data = b"hello world";
    let hash = SymCrypt::sha256(data);
    println!("SHA256 hash : {:?}", hash);



    let data = b"test test te";
    let hash = SymCrypt::sha256(data);
    println!("SHA256 hash : {:?}", hash);


    let data = b"phil and khang";
    let hash = SymCrypt::sha256(data);
    println!("SHA256 hash : {:?}", hash);
}
