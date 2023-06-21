use symcrypt::*;

fn main() {
    println!("Testing sha256! \n\n");

    let data = b"this is a test";
    let mut result: [u8; SHA256_RESULT_SIZE] = [0; SHA256_RESULT_SIZE];
    sha256(data, &mut result);
    println!("SHA256 stateless hash: {:?}", result);

    let mut sha_test = Sha256State::new();

    let mut result: [u8; SHA256_RESULT_SIZE] = [0; SHA256_RESULT_SIZE];
    Sha256State::append(&mut sha_test, data);
    Sha256State::result(&mut sha_test, &mut result);
    println!("SHA256 state hash: {:?}", result);

    println!("\n\n Testing sha384! \n\n");

    let data = b"this is a test";
    let mut result: [u8; SHA384_RESULT_SIZE] = [0; SHA384_RESULT_SIZE];
    sha384(data, &mut result);
    println!("SHA384 stateless hash: {:?}", result);

    let mut sha_test = Sha384State::new();

    let mut result: [u8; SHA384_RESULT_SIZE] = [0; SHA384_RESULT_SIZE];
    Sha384State::append(&mut sha_test, data);
    Sha384State::result(&mut sha_test, &mut result);
    println!("SHA384 state hash: {:?}", result);
}
