use crate::ops::{add_key, key_schedule, mix_columns, shift_rows, sub_bytes};
use crate::{AesBlock, AesKey};

fn _debug_state(state: AesBlock) {
    for i in 0..4 {
        for j in 0..4 {
            print!("{:02x} ", state.data[4 * j + i]);
        }
        print!("\n");
    }
    print!("\n");
}

pub(crate) fn encrypt(key: &AesKey, rounds: usize, block: AesBlock) -> AesBlock {
    let expanded_key = key_schedule(key, rounds);
    let mut state = block;
    add_key(&mut state, expanded_key[0]);
    for i in 1..rounds {
        sub_bytes(&mut state);
        shift_rows(&mut state);
        mix_columns(&mut state);
        add_key(&mut state, expanded_key[i]);
    }
    sub_bytes(&mut state);
    shift_rows(&mut state);
    add_key(&mut state, expanded_key[rounds]);
    state
}
