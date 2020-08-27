use crate::aes::key_schedule::AesKeySchedule;
use crate::aes::{AesBlock, AesDecrypt, AesKey, AES};

use super::add_key::add_key;
use super::mix_columns::inv_mix_columns;
use super::shift_rows::inv_shift_rows;
use super::sub_bytes::inv_sub_bytes;

fn _debug_state(state: AesBlock) {
    for i in 0..4 {
        for j in 0..4 {
            print!("{:02x} ", state.data[4 * j + i]);
        }
        print!("\n");
    }
    print!("\n");
}

impl<T: AesKey + AesKeySchedule> AesDecrypt<T> for AES {
    fn decrypt(key: T, block: AesBlock) -> AesBlock {
        let expanded_key = key.key_schedule();
        let nround = expanded_key.len();
        let mut state = block;
        add_key(&mut state, expanded_key[nround - 1]);
        inv_shift_rows(&mut state);
        inv_sub_bytes(&mut state);
        for i in (1..(nround - 1)).rev() {
            add_key(&mut state, expanded_key[i]);
            inv_mix_columns(&mut state);
            inv_shift_rows(&mut state);
            inv_sub_bytes(&mut state);
        }
        add_key(&mut state, expanded_key[0]);
        state
    }
}

