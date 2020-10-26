use super::super::*;
use super::AesBytesDecrypt;
use super::AesBytesEncrypt;
use super::{pad, unpad};

pub struct AesCbc;

macro_rules! impl_aesbytesencrypt_for_aescbc {
    ($keytype: ty) => {
        impl AesBytesEncrypt<$keytype> for AesCbc {
            fn encrypt(key: $keytype, bytes: &[u8]) -> Vec<AesBlock> {
                // generate iv
                let iv = AesBlock::with_random();
                // padding
                let padded = pad(bytes);

                // encrypt
                let len = padded.len();
                let mut encrypted = Vec::with_capacity(1 + len);
                encrypted.push(iv);
                for i in 0..len {
                    let block = padded[i];
                    let xored_block = block ^ *encrypted.last().unwrap();
                    encrypted.push(Aes::encrypt(key, xored_block));
                }

                encrypted
            }
        }
    };
}
impl_aesbytesencrypt_for_aescbc!(AesKey128);
impl_aesbytesencrypt_for_aescbc!(AesKey192);
impl_aesbytesencrypt_for_aescbc!(AesKey256);

macro_rules! impl_aesbytesdecrypt_for_aescbc {
    ($keytype: ty) => {
        impl AesBytesDecrypt<$keytype> for AesCbc {
            fn decrypt(key: $keytype, bytes: &[AesBlock]) -> Vec<u8> {
                // decrypt
                let len = bytes.len() - 1;
                let mut decrypted = Vec::with_capacity(len);
                for i in 0..len {
                    let before_block = bytes[i];
                    let cipher_block = bytes[i + 1];
                    decrypted.push(before_block ^ Aes::decrypt(key, cipher_block));
                }
                // unpad
                unpad(&decrypted)
            }
        }
    };
}
impl_aesbytesdecrypt_for_aescbc!(AesKey128);
impl_aesbytesdecrypt_for_aescbc!(AesKey192);
impl_aesbytesdecrypt_for_aescbc!(AesKey256);
