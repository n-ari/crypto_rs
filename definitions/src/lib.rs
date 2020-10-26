// Symmetric Key Encryption
pub trait SymmetricKeyEncryption {
    type Message;
    type Cipher;
    type Param;
    type SecretKey;
    fn new(param: &Self::Param) -> Self;
    fn gen_key(&self) -> Self::SecretKey;
    fn encrypt(&self, key: &Self::SecretKey, m: &Self::Message) -> Self::Cipher;
    fn decrypt(&self, key: &Self::SecretKey, c: &Self::Cipher) -> Self::Message;
}

// Public Key Encryption
pub trait PublicKeyEncryption {
    type Message;
    type Cipher;
    type Param;
    type SecretKey;
    type PublicKey;
    fn new(param: &Self::Param) -> Self;
    fn gen_key(&self) -> (Self::PublicKey, Self::SecretKey);
    fn encrypt(&self, key: &Self::PublicKey, m: &Self::Message) -> Self::Cipher;
    fn decrypt(&self, key: &Self::SecretKey, c: &Self::Cipher) -> Self::Message;
}
