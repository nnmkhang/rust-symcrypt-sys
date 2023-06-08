use symcrypt::*;

fn main() {
    println!("Hello World! \n\n");
    println!("If you comment out SymCryptSha256Algorithm code compiles,
    and links. SymCryptSha384Algorithm produces an AV. 
    this is expected and unrelated to the linking issue. \n");

    let mut result: u64 = 0;
    let mut result2: u64 = 0;
    unsafe{
        //result = symcrypt_sys::SymCryptHashStateSize(symcrypt_sys::SymCryptSha256Algorithm); // comment this out and NO compilation errors
        result2 = symcrypt_sys::SymCryptHashStateSize(symcrypt_sys::SymCryptSha384Algorithm) // this will lead to AV. this is expected 
    }
}
