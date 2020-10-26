use super::super::*;
use super::AesBytesDecrypt;
use super::AesBytesEncrypt;
use super::{pad, unpad};

pub struct AesCtr;

macro_rules! impl_aesbytesencrypt_for_aesctr {
    ($keytype: ty) => {
        impl AesBytesEncrypt<$keytype> for AesCtr {
            fn encrypt(key: $keytype, bytes: &[u8]) -> Vec<AesBlock> {
                // generate iv
                let iv = AesBlock::with_random();
                // padding
                let padded = pad(bytes);

                // encrypt
                let len = padded.len();
                let mut encrypted = Vec::with_capacity(1 + len);
                encrypted.push(iv);
                let mut ctr = u128::from(iv);
                for i in 0..len {
                    let block = padded[i];
                    let encrypted_ctr = Aes::encrypt(key, AesBlock::from(ctr));
                    encrypted.push(block ^ encrypted_ctr);
                    ctr = ctr.wrapping_add(1);
                }

                encrypted
            }
        }
    };
}
impl_aesbytesencrypt_for_aesctr!(AesKey128);
impl_aesbytesencrypt_for_aesctr!(AesKey192);
impl_aesbytesencrypt_for_aesctr!(AesKey256);

macro_rules! impl_aesbytesdecrypt_for_aesctr {
    ($keytype: ty) => {
        impl AesBytesDecrypt<$keytype> for AesCtr {
            fn decrypt(key: $keytype, bytes: &[AesBlock]) -> Vec<u8> {
                // decrypt
                let len = bytes.len() - 1;
                let mut decrypted = Vec::with_capacity(len);
                let mut ctr = u128::from(bytes[0]);
                for i in 0..len {
                    let cipher_block = bytes[i + 1];
                    let encrypted_ctr = Aes::encrypt(key, AesBlock::from(ctr));
                    decrypted.push(cipher_block ^ encrypted_ctr);
                    ctr = ctr.wrapping_add(1);
                }
                // unpad
                unpad(&decrypted)
            }
        }
    };
}
impl_aesbytesdecrypt_for_aesctr!(AesKey128);
impl_aesbytesdecrypt_for_aesctr!(AesKey192);
impl_aesbytesdecrypt_for_aesctr!(AesKey256);
