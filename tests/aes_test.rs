extern crate crypto_rs;
use crypto_rs::aes::*;

#[test]
fn it_encrypts_with_aes128() {
    let key = AesKey128::from("0123456789abcdef0123456789abcdef");
    let data = AesBlock::from("deadbeef830252521337655373170000");
    let encrypted = AES::encrypt(key, data);
    assert_eq!(encrypted.to_string(), "2e6b0c8c184901578ae5529bcb9ce953");
}

