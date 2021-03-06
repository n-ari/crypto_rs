use crate::AesBlock;

pub(crate) fn add_key(state: &mut AesBlock, key: AesBlock) {
    for i in 0..16 {
        state.data[i] ^= key.data[i];
    }
}
