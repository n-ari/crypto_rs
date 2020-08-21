use super::AesBlock;

pub mod cbc;
pub mod ctr;
pub mod gcm;

pub trait AesBytesEncrypt<T> {
    fn encrypt(key: T, bytes: &[u8]) -> Vec<AesBlock>;
}
pub trait AesBytesEncryptWithIv<T> {
    fn encrypt(key: T, iv: AesBlock, bytes: &[u8]) -> Vec<AesBlock>;
}
pub trait AesBytesDecrypt<T> {
    fn decrypt(key: T, bytes: &[AesBlock]) -> Vec<u8>;
}

