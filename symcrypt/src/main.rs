use symcrypt::SymCrypt;
use std::fs;


fn main() {
    

    // fs::copy("../../symcrypt-sys/inc/libsymcrypt.so", "../target/debug/libsymcrypt.so").unwrap();
    // fs::copy("../../symcrypt-sys/inc/libsymcrypt.so.103", "../target/debug/libsymcrypt.so.103").unwrap();
    // fs::copy("../../symcrypt-sys/inc/libsymcrypt.so.103.1.0", "../target/debug/libsymcrypt.so.103.1.0").unwrap();
    println!("Hello, world!");
    //SymCrypt::new();
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
