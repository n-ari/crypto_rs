#[derive(Debug, Copy, Clone)]
pub struct AesBlock {
    pub data: [u8; 16],
}
#[derive(Debug, Copy, Clone)]
pub struct AesKey128 {
    pub data: [u8; 16],
}
#[derive(Debug, Copy, Clone)]
pub struct AesKey192 {
    pub data: [u8; 24],
}
#[derive(Debug, Copy, Clone)]
pub struct AesKey256 {
    pub data: [u8; 32],
}

pub struct AES {}
pub trait AesEncrypt<T> {
    fn encrypt(key: T, data: AesBlock) -> AesBlock;
}
pub trait AesDecrypt<T> {
    fn decrypt(key: T, data: AesBlock);
}

mod utils;

mod sbox;

mod key_schedule;

mod add_key;
mod mix_columns;
mod shift_rows;
mod sub_bytes;

mod encrypt;

