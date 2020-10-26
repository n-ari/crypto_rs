use crate::ops::sbox::SBOX;
use crate::AesBlock;
use crate::AesKey;

fn lshift_for_gf256(x: u8) -> u8 {
    if (x & 0x80u8) == 0x80u8 {
        ((x ^ 0x80u8) << 1) ^ 0b00011011u8
    } else {
        x << 1
    }
}

fn xor_word(a: [u8; 4], b: [u8; 4]) -> [u8; 4] {
    [a[0] ^ b[0], a[1] ^ b[1], a[2] ^ b[2], a[3] ^ b[3]]
}
fn upshift_word(a: [u8; 4]) -> [u8; 4] {
    [a[1], a[2], a[3], a[0]]
}
#[rustfmt::skip]
fn apply_sbox_word(a: [u8; 4]) -> [u8; 4] {
    [
        SBOX[a[0] as usize], SBOX[a[1] as usize], SBOX[a[2] as usize], SBOX[a[3] as usize],
    ]
}

#[rustfmt::skip]
fn square_to_aes_block(square: &[[u8; 4]]) -> AesBlock {
    AesBlock {
        data: [
            square[0][0], square[0][1], square[0][2], square[0][3],
            square[1][0], square[1][1], square[1][2], square[1][3],
            square[2][0], square[2][1], square[2][2], square[2][3],
            square[3][0], square[3][1], square[3][2], square[3][3],
        ],
    }
}

pub fn key_schedule<T: AesKey>(key: T) -> Vec<AesBlock> {
    let data = key.data();
    let num_key = data.len() / 4;
    let mut expkey = vec![[0u8; 4]; 4 * (T::NUM_ROUND + 1)];
    // key to words
    for i in 0..num_key {
        for j in 0..4 {
            expkey[i][j] = data[4 * i + j];
        }
    }

    // calculate expanded key
    let mut rc = 0x01u8;
    for i in num_key..4 * (T::NUM_ROUND + 1) {
        expkey[i] = if i % num_key == 0 {
            let rc_ = rc;
            // update rc
            rc = lshift_for_gf256(rc);
            let sbox_word = apply_sbox_word(upshift_word(expkey[i - 1]));
            let rc_word = [rc_, 0, 0, 0];
            xor_word(xor_word(expkey[i - num_key], sbox_word), rc_word)
        } else if num_key > 6 && i % num_key == 4 {
            let sbox_word = apply_sbox_word(expkey[i - 1]);
            xor_word(expkey[i - num_key], sbox_word)
        } else {
            xor_word(expkey[i - num_key], expkey[i - 1])
        }
    }

    // convert to [AesBlock; $nround]
    let mut key = vec![AesBlock { data: [0u8; 16] }; T::NUM_ROUND + 1];
    for i in 0..(T::NUM_ROUND + 1) {
        key[i] = square_to_aes_block(&expkey[4 * i + 0..4 * i + 4]);
    }

    key
}
