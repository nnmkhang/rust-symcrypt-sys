use symcrypt::SymCrypt;

fn main() {
    println!("Hello, world!");
    //SymCrypt::new();
    let data = b"hello world";
    let hash = SymCrypt::sha256(data);
    println!("SHA256 hash : {:?}", hash);

    let data = b"test test test";
    let hash = SymCrypt::sha256(data);
    println!("SHA256 hash : {:?}", hash);

    let data = b"phil and khang";
    let hash = SymCrypt::sha256(data);
    println!("SHA256 hash : {:?}", hash);
}
