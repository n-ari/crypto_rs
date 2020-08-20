use super::AesBlock;

pub(super) fn shift_rows(state: &mut AesBlock) {
    fn rotate(state: &mut AesBlock, row: usize) {
        let tmp = state.data[4 * 0 + row];
        state.data[4 * 0 + row] = state.data[4 * 1 + row];
        state.data[4 * 1 + row] = state.data[4 * 2 + row];
        state.data[4 * 2 + row] = state.data[4 * 3 + row];
        state.data[4 * 3 + row] = tmp;
    }
    rotate(state, 1);
    rotate(state, 2);
    rotate(state, 2);
    rotate(state, 3);
    rotate(state, 3);
    rotate(state, 3);
}

