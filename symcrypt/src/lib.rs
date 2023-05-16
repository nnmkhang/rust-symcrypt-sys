use symcrypt_sys::*;

pub struct SymCrypt;

impl SymCrypt {
    pub fn new () {
        unsafe 
        { 
            symcrypt_sys::SymCryptInit();
        }
    }

    pub fn Sha256(data: &[u8]) -> [u8; 32] {
        let mut hash = [0u8; 32];
        
        // Call the SymCrypt function using the generated bindings
        unsafe {
            println!("we're inside symcryptsha");
            symcrypt_sys::SymCryptSha256(
                data.as_ptr(), // pbData
                data.len() as symcrypt_sys::SIZE_T, //cbData
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
        //SymCrypt::new();

        let data = b"hello world";
        let hash = SymCrypt::sha256(data);
        println!("SHA256 hash : {:?}", hash);
        
    }
}