use super::super::*;
use super::AesBytesDecrypt;
use super::AesBytesEncrypt;

pub struct AESCTR;

macro_rules! impl_aesbytesencrypt_for_aesctr {
    ($keytype: ty) => {
        impl AesBytesEncrypt<$keytype> for AESCTR {
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
                let mut ctr = u128::from(iv);
                for i in 0..len {
                    let block = AesBlock::from(&padded[16 * i..16 * (i + 1)]);
                    let encrypted_ctr = AES::encrypt(key, AesBlock::from(ctr));
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
        impl AesBytesDecrypt<$keytype> for AESCTR {
            fn decrypt(key: $keytype, bytes: &[AesBlock]) -> Vec<u8> {
                // decrypt
                let len = bytes.len() - 1;
                let mut decrypted = Vec::with_capacity(len);
                let mut ctr = u128::from(bytes[0]);
                for i in 0..len {
                    let cipher_block = bytes[i + 1];
                    let encrypted_ctr = AES::encrypt(key, AesBlock::from(ctr));
                    decrypted.push(cipher_block ^ encrypted_ctr);
                    ctr = ctr.wrapping_add(1);
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
impl_aesbytesdecrypt_for_aesctr!(AesKey128);
impl_aesbytesdecrypt_for_aesctr!(AesKey192);
impl_aesbytesdecrypt_for_aesctr!(AesKey256);

