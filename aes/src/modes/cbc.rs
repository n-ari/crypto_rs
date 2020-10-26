use super::{pad, unpad};
use crate::*;
use definitions::SymmetricKeyEncryption;

pub struct AesCbc {
    aes: Aes,
}

impl SymmetricKeyEncryption for AesCbc {
    type Message = Vec<u8>;
    type Cipher = Vec<AesBlock>;
    type Param = AesKeySize;
    type SecretKey = AesKey;
    fn new(param: &Self::Param) -> Self {
        Self {
            aes: Aes::new(param),
        }
    }
    fn gen_key(&self) -> Self::SecretKey {
        self.aes.gen_key()
    }
    fn encrypt(&self, key: &Self::SecretKey, m: &Self::Message) -> Self::Cipher {
        // generate iv
        let iv = AesBlock::with_random();
        // padding
        let padded = pad(m);

        // encrypt
        let len = padded.len();
        let mut encrypted = Vec::with_capacity(1 + len);
        encrypted.push(iv);
        for i in 0..len {
            let block = padded[i];
            let xored_block = block ^ *encrypted.last().unwrap();
            encrypted.push(self.aes.encrypt(key, &xored_block));
        }

        encrypted
    }
    fn decrypt(&self, key: &Self::SecretKey, c: &Self::Cipher) -> Self::Message {
        // decrypt
        let len = c.len() - 1;
        let mut decrypted = Vec::with_capacity(len);
        for i in 0..len {
            let before_block = c[i];
            let cipher_block = c[i + 1];
            decrypted.push(before_block ^ self.aes.decrypt(key, &cipher_block));
        }
        // unpad
        unpad(&decrypted)
    }
}
