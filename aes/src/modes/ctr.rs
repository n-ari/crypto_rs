use super::{pad, unpad};
use crate::*;
use definitions::SymmetricKeyEncryption;

pub struct AesCtr {
    aes: Aes,
}

impl SymmetricKeyEncryption for AesCtr {
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
        let mut ctr = u128::from(iv);
        for i in 0..len {
            let block = padded[i];
            let encrypted_ctr = self.aes.encrypt(key, &AesBlock::from(ctr));
            encrypted.push(block ^ encrypted_ctr);
            ctr = ctr.wrapping_add(1);
        }

        encrypted
    }
    fn decrypt(&self, key: &Self::SecretKey, c: &Self::Cipher) -> Self::Message {
        // decrypt
        let len = c.len() - 1;
        let mut decrypted = Vec::with_capacity(len);
        let mut ctr = u128::from(c[0]);
        for i in 0..len {
            let cipher_block = c[i + 1];
            let encrypted_ctr = self.aes.encrypt(key, &AesBlock::from(ctr));
            decrypted.push(cipher_block ^ encrypted_ctr);
            ctr = ctr.wrapping_add(1);
        }
        // unpad
        unpad(&decrypted)
    }
}
