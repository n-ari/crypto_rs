use crate::AesBlock;

fn rotate(state: &mut AesBlock, row: usize) {
    let tmp = state.data[4 * 0 + row];
    state.data[4 * 0 + row] = state.data[4 * 1 + row];
    state.data[4 * 1 + row] = state.data[4 * 2 + row];
    state.data[4 * 2 + row] = state.data[4 * 3 + row];
    state.data[4 * 3 + row] = tmp;
}

pub(crate) fn shift_rows(state: &mut AesBlock) {
    rotate(state, 1);
    rotate(state, 2);
    rotate(state, 2);
    rotate(state, 3);
    rotate(state, 3);
    rotate(state, 3);
}

pub(crate) fn inv_shift_rows(state: &mut AesBlock) {
    rotate(state, 1);
    rotate(state, 1);
    rotate(state, 1);
    rotate(state, 2);
    rotate(state, 2);
    rotate(state, 3);
}
