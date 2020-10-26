use crate::ops::{add_key, key_schedule, mix_columns, shift_rows, sub_bytes};
use crate::{Aes, AesBlock, AesEncrypt, AesKey};

fn _debug_state(state: AesBlock) {
    for i in 0..4 {
        for j in 0..4 {
            print!("{:02x} ", state.data[4 * j + i]);
        }
        print!("\n");
    }
    print!("\n");
}

impl<T: AesKey> AesEncrypt<T> for Aes {
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
