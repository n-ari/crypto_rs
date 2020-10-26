#[derive(Debug, Copy, Clone)]
pub struct AesBlock {
    pub data: [u8; 16],
}

#[derive(Debug, Clone)]
pub struct AesKey(Vec<u8>);

#[derive(Debug, Copy, Clone)]
pub enum AesKeySize {
    Aes128,
    Aes192,
    Aes256,
}
impl AesKeySize {
    pub fn len_bytes(&self) -> usize {
        match self {
            AesKeySize::Aes128 => 16,
            AesKeySize::Aes192 => 24,
            AesKeySize::Aes256 => 32,
        }
    }
    pub fn rounds(&self) -> usize {
        match self {
            AesKeySize::Aes128 => 10,
            AesKeySize::Aes192 => 12,
            AesKeySize::Aes256 => 14,
        }
    }
    pub fn gen_key_bytes(&self) -> Vec<u8> {
        use rand::{distributions::Standard, Rng};
        let len = self.len_bytes();
        rand::thread_rng()
            .sample_iter(Standard)
            .take(len)
            .collect::<Vec<_>>()
    }
}

pub use definitions::SymmetricKeyEncryption;
#[derive(Debug, Copy, Clone)]
pub struct Aes {
    keysize: AesKeySize,
}
impl SymmetricKeyEncryption for Aes {
    type Message = AesBlock;
    type Cipher = AesBlock;
    type Param = AesKeySize;
    type SecretKey = AesKey;
    fn new(param: &Self::Param) -> Self {
        Self { keysize: *param }
    }
    fn gen_key(&self) -> Self::SecretKey {
        AesKey(self.keysize.gen_key_bytes())
    }
    fn encrypt(&self, key: &Self::SecretKey, m: &Self::Message) -> Self::Cipher {
        encrypt::encrypt(key, self.keysize.rounds(), *m)
    }
    fn decrypt(&self, key: &Self::SecretKey, c: &Self::Cipher) -> Self::Message {
        decrypt::decrypt(key, self.keysize.rounds(), *c)
    }
}

mod decrypt;
mod encrypt;
mod ops;
mod utils;

mod modes;
pub use self::modes::{cbc::AesCbc, ctr::AesCtr};
