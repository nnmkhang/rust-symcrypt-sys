extern crate libc;

#[allow(non_upper_case_globals)]
#[allow(non_camel_case_types)]
#[allow(non_snake_case)]

pub mod ffi {
    include!(concat!(env!("OUT_DIR"), "/bindings.rs"));
}

#[non_exhaustive] // External users cannot construct or destruct a SymCrypt, must use the constructors that we make
#[derive(Clone, Debug)]
pub struct SymCrypt;

impl SymCrypt {
    pub fn new () {
        unsafe 
        { 
            // ffi::SymCryptInit();
        }
    }

    pub fn sha256(data: &[u8]) -> [u8; 32] {
        let mut hash = [0u8; 32];
        
        // Call the SymCrypt function using the generated bindings
        unsafe {
            println!("we're inside symcryptsha");
            ffi::SymCryptSha256(
                data.as_ptr(), // pbData
                data.len() as ffi::SIZE_T, //cbData
                hash.as_mut_ptr() //pbResult
            );
        }
        hash
    }
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_works() {
        println!("inside test function");
        SymCrypt::new();

        let data = b"hello world";
        let hash = SymCrypt::sha256(data);
        println!("SHA256 hash : {:?}", hash);
        
    }
}