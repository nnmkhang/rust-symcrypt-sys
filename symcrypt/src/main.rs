use symcrypt::SymCryptSha256;

fn main() {
    println!("Hello, world!");

    let mut result = [0u8; 32];

    let data = b"this is a test";
    SymCryptSha256::sha256(data, &mut result);
    println!("SHA256 hash: {:?}", result);

    let mut sha_test = SymCryptSha256::new();
    SymCryptSha256::append(&mut sha_test, b"this is a test");
    let mut result = [0u8; 32];
    SymCryptSha256::result(&mut sha_test, &mut result);
    println!("result: {:?}", result);
    println!("done");
    
}
