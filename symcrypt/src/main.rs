use symcrypt::*;

fn main() {
    println!("Testing sha256! \n\n");

    let data = b"this is a test";
    let mut result: [u8; 32] = [0; 32];
    sha256(data, &mut result);
    println!("SHA256 stateless hash: {:?}", result);

    let mut sha_test = Sha256State::new();
    println!("State for sha_test = {:?}", sha_test.state);

    let mut result: [u8; 32] = [0; 32];
    Sha256State::append(&mut sha_test, b"this is a test");
    Sha256State::result(&mut sha_test, &mut result);
    println!("SHA256 state hash: {:?}", result);

    println!("\n\n Testing sha384! \n\n");

    let data = b"this is a test";
    let mut result: [u8; 48] = [0; 48];
    sha384(data, &mut result);
    println!("SHA384 stateless hash: {:?}", result);

    let mut sha_test = Sha384State::new();
    println!("State for sha_test = {:?}", sha_test.state);

    let mut result: [u8; 48] = [0; 48];
    Sha384State::append(&mut sha_test, b"this is a test");
    Sha384State::result(&mut sha_test, &mut result);
    println!("SHA384 state hash: {:?}", result);


    // unsafe{
    //     println!("{:?}", (symcrypt_sys::SymCryptSha256Algorithm).try_into()); //0x25ff0000234225ff
    //     println!("{:?}", symcrypt_sys::SymCryptHashStateSize as *const());
    //     let result = check_hash_size();
    //     println!("{:?}", result);
        
    // }
}
