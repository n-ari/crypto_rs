use crate::AesBlock;

fn mul(a: u8, b: u8) -> u8 {
    let mut ret = 0u8;
    let mut aa = a;
    let mut bb = b;
    while bb > 0 {
        if (bb & 1) == 1 {
            ret ^= aa;
        }
        bb >>= 1;
        aa = if aa >= 0x80u8 {
            ((aa ^ 0x80u8) << 1) ^ 0b00011011u8
        } else {
            aa << 1
        };
    }
    ret
}

pub(crate) fn mix_columns(state: &mut AesBlock) {
    for i in 0..4 {
        let [a, b, c, d] = [
            state.data[4 * i + 0],
            state.data[4 * i + 1],
            state.data[4 * i + 2],
            state.data[4 * i + 3],
        ];
        state.data[4 * i + 0] = mul(a, 2) ^ mul(b, 3) ^ mul(c, 1) ^ mul(d, 1);
        state.data[4 * i + 1] = mul(a, 1) ^ mul(b, 2) ^ mul(c, 3) ^ mul(d, 1);
        state.data[4 * i + 2] = mul(a, 1) ^ mul(b, 1) ^ mul(c, 2) ^ mul(d, 3);
        state.data[4 * i + 3] = mul(a, 3) ^ mul(b, 1) ^ mul(c, 1) ^ mul(d, 2);
    }
}

pub(crate) fn inv_mix_columns(state: &mut AesBlock) {
    for i in 0..4 {
        let [a, b, c, d] = [
            state.data[4 * i + 0],
            state.data[4 * i + 1],
            state.data[4 * i + 2],
            state.data[4 * i + 3],
        ];
        state.data[4 * i + 0] = mul(a, 14) ^ mul(b, 11) ^ mul(c, 13) ^ mul(d, 9);
        state.data[4 * i + 1] = mul(a, 9) ^ mul(b, 14) ^ mul(c, 11) ^ mul(d, 13);
        state.data[4 * i + 2] = mul(a, 13) ^ mul(b, 9) ^ mul(c, 14) ^ mul(d, 11);
        state.data[4 * i + 3] = mul(a, 11) ^ mul(b, 13) ^ mul(c, 9) ^ mul(d, 14);
    }
}
