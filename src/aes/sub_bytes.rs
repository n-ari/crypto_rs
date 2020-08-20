use super::sbox;
use super::AesBlock;

pub(super) fn sub_bytes(state: &mut AesBlock) {
    for i in 0..16 {
        state.data[i] = sbox::SBOX[state.data[i] as usize];
    }
}
