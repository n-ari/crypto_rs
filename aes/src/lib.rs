#[derive(Debug, Copy, Clone)]
pub struct AesBlock {
    pub data: [u8; 16],
}

pub trait AesKey {
    const NUM_ROUND: usize;
    fn data(&self) -> &[u8];
}

#[derive(Debug, Copy, Clone)]
pub struct AesKey128 {
    pub data: [u8; 16],
}
impl AesKey for AesKey128 {
    const NUM_ROUND: usize = 10;
    fn data(&self) -> &[u8] {
        &self.data
    }
}

#[derive(Debug, Copy, Clone)]
pub struct AesKey192 {
    pub data: [u8; 24],
}
impl AesKey for AesKey192 {
    const NUM_ROUND: usize = 12;
    fn data(&self) -> &[u8] {
        &self.data
    }
}

#[derive(Debug, Copy, Clone)]
pub struct AesKey256 {
    pub data: [u8; 32],
}
impl AesKey for AesKey256 {
    const NUM_ROUND: usize = 14;
    fn data(&self) -> &[u8] {
        &self.data
    }
}

pub struct Aes {}
pub trait AesEncrypt<T: AesKey> {
    fn encrypt(key: T, data: AesBlock) -> AesBlock;
}
pub trait AesDecrypt<T: AesKey> {
    fn decrypt(key: T, data: AesBlock) -> AesBlock;
}

mod decrypt;
mod encrypt;
mod ops;
mod utils;

mod modes;
pub use self::modes::{cbc::AesCbc, ctr::AesCtr};
pub use self::modes::{AesBytesDecrypt, AesBytesEncrypt, AesBytesEncryptWithIv};
