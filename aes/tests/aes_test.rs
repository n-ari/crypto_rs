use aes::*;

#[test]
fn it_encrypts_with_aes128() {
    let aes = Aes::new(&AesKeySize::Aes128);
    let key = AesKey::from("0123456789abcdef0123456789abcdef");
    let data = AesBlock::from("deadbeef830252521337655373170000");
    let encrypted = aes.encrypt(&key, &data);
    assert_eq!(encrypted.to_string(), "2e6b0c8c184901578ae5529bcb9ce953");
}

#[test]
fn it_encrypts_with_aes192() {
    let aes = Aes::new(&AesKeySize::Aes192);
    let key = AesKey::from("0123456789abcdef0123456789abcdef0123456789abcdef");
    let data = AesBlock::from("deadbeef830252521337655373170000");
    let encrypted = aes.encrypt(&key, &data);
    assert_eq!(encrypted.to_string(), "3cfab87bbe03b650b444665b384e8b7e");
}

#[test]
fn it_encrypts_with_aes256() {
    let aes = Aes::new(&AesKeySize::Aes256);
    let key = AesKey::from("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef");
    let data = AesBlock::from("deadbeef830252521337655373170000");
    let encrypted = aes.encrypt(&key, &data);
    assert_eq!(encrypted.to_string(), "87d9f5cc4266093bad532c512e7adc35");
}

#[test]
fn it_decrypts_with_aes128() {
    let aes = Aes::new(&AesKeySize::Aes128);
    let key = AesKey::from("0123456789abcdef0123456789abcdef");
    let data = AesBlock::from("2e6b0c8c184901578ae5529bcb9ce953");
    let decrypted = aes.decrypt(&key, &data);
    assert_eq!(decrypted.to_string(), "deadbeef830252521337655373170000");
}

#[test]
fn it_decrypts_with_aes192() {
    let aes = Aes::new(&AesKeySize::Aes192);
    let key = AesKey::from("0123456789abcdef0123456789abcdef0123456789abcdef");
    let data = AesBlock::from("3cfab87bbe03b650b444665b384e8b7e");
    let decrypted = aes.decrypt(&key, &data);
    assert_eq!(decrypted.to_string(), "deadbeef830252521337655373170000");
}

#[test]
fn it_decrypts_with_aes256() {
    let aes = Aes::new(&AesKeySize::Aes256);
    let key = AesKey::from("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef");
    let data = AesBlock::from("87d9f5cc4266093bad532c512e7adc35");
    let decrypted = aes.decrypt(&key, &data);
    assert_eq!(decrypted.to_string(), "deadbeef830252521337655373170000");
}

#[test]
fn it_recover_text_with_aes128cbc() {
    let aes = AesCbc::new(&AesKeySize::Aes128);
    let key = AesKey::from("0123456789abcdef0123456789abcdef");
    let data_str = "Hello world! This is a test for AES encryption with CBC mode!!";
    let data_bytes = data_str.as_bytes().to_vec();
    let encrypted = aes.encrypt(&key, &data_bytes);
    let decrypted = aes.decrypt(&key, &encrypted);
    assert_eq!(data_bytes.to_vec(), decrypted);
}

#[test]
fn it_recover_text_with_aes128ctr() {
    let aes = AesCtr::new(&AesKeySize::Aes128);
    let key = AesKey::from("0123456789abcdef0123456789abcdef");
    let data_str = "Hello world! This is a test for AES encryption with CTR mode!!";
    let data_bytes = data_str.as_bytes().to_vec();
    let encrypted = aes.encrypt(&key, &data_bytes);
    let decrypted = aes.decrypt(&key, &encrypted);
    assert_eq!(data_bytes.to_vec(), decrypted);
}
