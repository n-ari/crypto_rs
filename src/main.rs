extern crate crypto_rs;
use crypto_rs::aes::*;

fn main() {
    let key = AesKey128::from("0123456789abcdef0123456789abcdef");
    let data = AesBlock::from("deadbeef830252521337655373170000");
    println!("key: {}, data: {}", key.to_string(), data.to_string());
    let encrypted = AES::encrypt(key, data);
    println!("{}", encrypted.to_string());
    // 2e6b0c8c184901578ae5529bcb9ce953
}

