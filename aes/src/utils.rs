use rand::Rng;
use std::ops::BitXor;
use std::str;
use std::u8;

use super::AesBlock;
use super::AesKey128;
use super::AesKey192;
use super::AesKey256;

// to_string methods
fn u8_array_to_string(array: &[u8]) -> String {
    let mut ret = String::new();
    for x in array.iter() {
        ret.push_str(format!("{:02x}", x).as_str());
    }
    ret
}
macro_rules! impl_tostring_for {
    ($type: ident) => {
        impl ToString for $type {
            fn to_string(&self) -> String {
                u8_array_to_string(&self.data)
            }
        }
    };
}
impl_tostring_for!(AesBlock);
impl_tostring_for!(AesKey128);
impl_tostring_for!(AesKey192);
impl_tostring_for!(AesKey256);

// from methods
fn str_to_u8_vec(data: &str) -> Vec<u8> {
    assert_eq!(data.len() % 2, 0);
    let chunks = data
        .as_bytes()
        .chunks(2)
        .map(str::from_utf8)
        .collect::<Result<Vec<&str>, _>>()
        .unwrap();
    chunks
        .iter()
        .map(|s| u8::from_str_radix(s, 16))
        .collect::<Result<Vec<u8>, _>>()
        .unwrap()
}
macro_rules! str_to_u8_array {
    ($str:expr, $n:expr) => {{
        let vec = str_to_u8_vec($str);
        assert_eq!(vec.len(), $n);
        let mut data = [0u8; $n];
        for i in 0..$n {
            data[i] = vec[i];
        }
        data
    }};
}
macro_rules! impl_from_str_for {
    ($type:ident, $n:expr) => {
        impl From<&str> for $type {
            fn from(string: &str) -> $type {
                $type {
                    data: str_to_u8_array!(string, $n),
                }
            }
        }
    };
}
impl_from_str_for!(AesBlock, 16);
impl_from_str_for!(AesKey128, 16);
impl_from_str_for!(AesKey192, 24);
impl_from_str_for!(AesKey256, 32);

macro_rules! impl_from_u8_slice_for {
    ($type:ident, $n:expr) => {
        impl From<&[u8]> for $type {
            fn from(slice: &[u8]) -> $type {
                assert_eq!(slice.len(), $n);
                let mut data = [0u8; $n];
                for i in 0..$n {
                    data[i] = slice[i];
                }
                $type { data }
            }
        }
    };
}
impl_from_u8_slice_for!(AesBlock, 16);
impl_from_u8_slice_for!(AesKey128, 16);
impl_from_u8_slice_for!(AesKey192, 24);
impl_from_u8_slice_for!(AesKey256, 32);

// random generator
macro_rules! impl_with_random_for {
    ($type:ident, $n:expr) => {
        impl $type {
            pub fn with_random() -> $type {
                let mut data = [0u8; $n];
                let mut rng = rand::thread_rng();
                rng.fill(&mut data);
                $type { data }
            }
        }
    };
}
impl_with_random_for!(AesBlock, 16);
impl_with_random_for!(AesKey128, 16);
impl_with_random_for!(AesKey192, 24);
impl_with_random_for!(AesKey256, 32);

// u128 <-> AesBlock
impl From<u128> for AesBlock {
    fn from(x: u128) -> AesBlock {
        AesBlock {
            data: x.to_be_bytes(),
        }
    }
}
impl From<AesBlock> for u128 {
    fn from(block: AesBlock) -> u128 {
        u128::from_be_bytes(block.data)
    }
}

impl BitXor for AesBlock {
    type Output = Self;
    fn bitxor(self, rhs: Self) -> Self::Output {
        let mut data = [0u8; 16];
        for i in 0..16 {
            data[i] = self.data[i] ^ rhs.data[i];
        }
        AesBlock { data }
    }
}
