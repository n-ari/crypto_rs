use crate::ops::{add_key, inv_mix_columns, inv_shift_rows, inv_sub_bytes, key_schedule};
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

pub(crate) fn decrypt(key: &AesKey, rounds: usize, block: AesBlock) -> AesBlock {
    let expanded_key = key_schedule(key, rounds);
    let mut state = block;
    add_key(&mut state, expanded_key[rounds]);
    inv_shift_rows(&mut state);
    inv_sub_bytes(&mut state);
    for i in (1..rounds).rev() {
        add_key(&mut state, expanded_key[i]);
        inv_mix_columns(&mut state);
        inv_shift_rows(&mut state);
        inv_sub_bytes(&mut state);
    }
    add_key(&mut state, expanded_key[0]);
    state
}
