use crate::key_schedule::key_schedule;
use crate::{AesBlock, AesEncrypt, AesKey, AES};

use super::add_key::add_key;
use super::mix_columns::mix_columns;
use super::shift_rows::shift_rows;
use super::sub_bytes::sub_bytes;

fn _debug_state(state: AesBlock) {
    for i in 0..4 {
        for j in 0..4 {
            print!("{:02x} ", state.data[4 * j + i]);
        }
        print!("\n");
    }
    print!("\n");
}

impl<T: AesKey> AesEncrypt<T> for AES {
    fn encrypt(key: T, block: AesBlock) -> AesBlock {
        let expanded_key = key_schedule(key);
        let nround = expanded_key.len();
        let mut state = block;
        add_key(&mut state, expanded_key[0]);
        for i in 1..(nround - 1) {
            sub_bytes(&mut state);
            shift_rows(&mut state);
            mix_columns(&mut state);
            add_key(&mut state, expanded_key[i]);
        }
        sub_bytes(&mut state);
        shift_rows(&mut state);
        add_key(&mut state, expanded_key[nround - 1]);
        state
    }
}

