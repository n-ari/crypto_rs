use super::AesBlock;

pub(super) fn mix_columns(state: &mut AesBlock) {
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

