use super::super::*;
use super::AesBytesDecrypt;
use super::AesBytesEncrypt;

pub struct AESCBC;

macro_rules! impl_aesbytesencrypt_for_aescbc {
    ($keytype: ty) => {
        impl AesBytesEncrypt<$keytype> for AESCBC {
            fn encrypt(key: $keytype, bytes: &[u8]) -> Vec<AesBlock> {
                // generate iv
                let iv = AesBlock::with_random();
                // padding
                let len = bytes.len() / 16 + 1;
                let mut padded = Vec::with_capacity(16 * len);
                padded.extend(bytes.iter().cloned());
                let remainder = 16 * len - bytes.len();
                for _ in 0..remainder {
                    padded.push(remainder as u8);
                }

                // encrypt
                let mut encrypted = Vec::with_capacity(1 + len);
                encrypted.push(iv);
                for i in 0..len {
                    let block = AesBlock::from(&padded[16 * i..16 * (i + 1)]);
                    let block = block ^ *encrypted.last().unwrap();
                    encrypted.push(AES::encrypt(key, block));
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
        impl AesBytesDecrypt<$keytype> for AESCBC {
            fn decrypt(key: $keytype, bytes: &[AesBlock]) -> Vec<u8> {
                // decrypt
                let len = bytes.len() - 1;
                let mut decrypted = Vec::with_capacity(len);
                for i in 0..len {
                    let before_block = bytes[i];
                    let cipher_block = bytes[i + 1];
                    decrypted.push(before_block ^ AES::decrypt(key, cipher_block));
                }
                // unpad
                let padded_len = decrypted[len - 1].data[15];
                let original_len = 16 * len - (padded_len as usize);
                let last_len = 16 - (padded_len as usize);
                let mut ret = Vec::with_capacity(original_len);
                for i in 0..len - 1 {
                    ret.extend(decrypted[i].data.iter());
                }
                ret.extend(decrypted[len - 1].data[0..last_len].iter());

                ret
            }
        }
    };
}
impl_aesbytesdecrypt_for_aescbc!(AesKey128);
impl_aesbytesdecrypt_for_aescbc!(AesKey192);
impl_aesbytesdecrypt_for_aescbc!(AesKey256);

