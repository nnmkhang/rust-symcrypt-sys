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
    //&my_struct as *const _
}

// 0:000> dq 0x7ff7763ddf90
// 00007ff7`763ddf90  25ff0000`235225ff 233e25ff`00002304
// 00007ff7`763ddfa0  00002330`25ff0000 25ff0000`232225ff
// 00007ff7`763ddfb0  230625ff`00002314 000022f8`25ff0000
// 00007ff7`763ddfc0  25ff0000`22e225ff 207625ff`000022e4
// 00007ff7`763ddfd0  000020a0`25ff0000 25ff0000`20a225ff
// 00007ff7`763ddfe0  211625ff`000020ac 00002118`25ff0000
// 00007ff7`763ddff0  cccc0000`211a25ff 01b920ec`83485340
// 00007ff7`763de000  00000b19`e8000000 e8c88b00`0005fbe8

// TODO: confirm size of Sha256 structure matches what is actually used