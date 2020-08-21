extern crate crypto_rs;
use crypto_rs::aes::modes::{cbc::*, ctr::*, *};
use crypto_rs::aes::*;

#[test]
fn it_encrypts_with_aes128() {
    let key = AesKey128::from("0123456789abcdef0123456789abcdef");
    let data = AesBlock::from("deadbeef830252521337655373170000");
    let encrypted = AES::encrypt(key, data);
    assert_eq!(encrypted.to_string(), "2e6b0c8c184901578ae5529bcb9ce953");
}

#[test]
fn it_encrypts_with_aes192() {
    let key = AesKey192::from("0123456789abcdef0123456789abcdef0123456789abcdef");
    let data = AesBlock::from("deadbeef830252521337655373170000");
    let encrypted = AES::encrypt(key, data);
    assert_eq!(encrypted.to_string(), "3cfab87bbe03b650b444665b384e8b7e");
}

#[test]
fn it_encrypts_with_aes256() {
    let key = AesKey256::from("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef");
    let data = AesBlock::from("deadbeef830252521337655373170000");
    let encrypted = AES::encrypt(key, data);
    assert_eq!(encrypted.to_string(), "87d9f5cc4266093bad532c512e7adc35");
}

#[test]
fn it_decrypts_with_aes128() {
    let key = AesKey128::from("0123456789abcdef0123456789abcdef");
    let data = AesBlock::from("2e6b0c8c184901578ae5529bcb9ce953");
    let decrypted = AES::decrypt(key, data);
    assert_eq!(decrypted.to_string(), "deadbeef830252521337655373170000");
}

#[test]
fn it_decrypts_with_aes192() {
    let key = AesKey192::from("0123456789abcdef0123456789abcdef0123456789abcdef");
    let data = AesBlock::from("3cfab87bbe03b650b444665b384e8b7e");
    let decrypted = AES::decrypt(key, data);
    assert_eq!(decrypted.to_string(), "deadbeef830252521337655373170000");
}

#[test]
fn it_decrypts_with_aes256() {
    let key = AesKey256::from("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef");
    let data = AesBlock::from("87d9f5cc4266093bad532c512e7adc35");
    let decrypted = AES::decrypt(key, data);
    assert_eq!(decrypted.to_string(), "deadbeef830252521337655373170000");
}

#[test]
fn it_recover_text_with_aes128cbc() {
    let key = AesKey128::from("0123456789abcdef0123456789abcdef");
    let data_str = "Hello world! This is a test for AES encryption with CBC mode!!";
    let data_bytes = data_str.as_bytes();
    let encrypted = AESCBC::encrypt(key, &data_bytes);
    let decrypted = AESCBC::decrypt(key, &encrypted);
    assert_eq!(data_bytes.to_vec(), decrypted);
}

#[test]
fn it_recover_text_with_aes128ctr() {
    let key = AesKey128::from("0123456789abcdef0123456789abcdef");
    let data_str = "Hello world! This is a test for AES encryption with CTR mode!!";
    let data_bytes = data_str.as_bytes();
    let encrypted = AESCTR::encrypt(key, &data_bytes);
    let decrypted = AESCTR::decrypt(key, &encrypted);
    assert_eq!(data_bytes.to_vec(), decrypted);
}

