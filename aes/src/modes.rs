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

fn pad(bytes: &[u8]) -> Vec<AesBlock> {
    let len = bytes.len() / 16 + 1;
    let mut padded = Vec::with_capacity(16 * len);
    padded.extend(bytes.iter().cloned());
    let remainder = 16 * len - bytes.len();
    for _ in 0..remainder {
        padded.push(remainder as u8);
    }
    padded
        .chunks(16)
        .map(|slice| AesBlock::from(slice))
        .collect()
}

fn unpad(blocks: &[AesBlock]) -> Vec<u8> {
    let bytes = blocks
        .iter()
        .flat_map(|block| block.data.iter().cloned())
        .collect::<Vec<u8>>();
    let len = bytes.len();
    let padded_len = bytes[len - 1];
    let original_len = len - (padded_len as usize);
    bytes[0..original_len].to_vec()
}
