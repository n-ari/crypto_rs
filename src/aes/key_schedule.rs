use super::sbox::SBOX;
use super::AesBlock;
use super::AesKey128;
// use super::AesKey192;
// use super::AesKey256;

// key schedule
impl AesKey128 {
    pub(super) fn key_schedule(&self) -> [AesBlock; 11] {
        let mut expkey = [[0u8; 4]; 4 * 11];
        for i in 0..4 {
            for j in 0..4 {
                expkey[i][j] = self.data[4 * i + j];
            }
        }

        // calculate expanded key
        let mut rc = 0x01u8;
        for i in 4..4 * 11 {
            expkey[i] = if i % 4 == 0 {
                let rc_ = rc;
                // update rc
                rc = if (rc & 0x80u8) == 0x80u8 {
                    ((rc ^ 0x80u8) << 1) ^ 0b00011011u8
                } else {
                    rc << 1
                };
                [
                    expkey[i - 4][0] ^ SBOX[expkey[i - 1][1] as usize] ^ rc_,
                    expkey[i - 4][1] ^ SBOX[expkey[i - 1][2] as usize],
                    expkey[i - 4][2] ^ SBOX[expkey[i - 1][3] as usize],
                    expkey[i - 4][3] ^ SBOX[expkey[i - 1][0] as usize],
                ]
            } else {
                [
                    expkey[i - 4][0] ^ expkey[i - 1][0],
                    expkey[i - 4][1] ^ expkey[i - 1][1],
                    expkey[i - 4][2] ^ expkey[i - 1][2],
                    expkey[i - 4][3] ^ expkey[i - 1][3],
                ]
            }
        }

        // convert to [AesBlock; 11]
        let mut key = [AesBlock { data: [0u8; 16] }; 11];
        for i in 0..11 {
            key[i] = AesBlock {
                data: [
                    expkey[4 * i + 0][0],
                    expkey[4 * i + 0][1],
                    expkey[4 * i + 0][2],
                    expkey[4 * i + 0][3],
                    expkey[4 * i + 1][0],
                    expkey[4 * i + 1][1],
                    expkey[4 * i + 1][2],
                    expkey[4 * i + 1][3],
                    expkey[4 * i + 2][0],
                    expkey[4 * i + 2][1],
                    expkey[4 * i + 2][2],
                    expkey[4 * i + 2][3],
                    expkey[4 * i + 3][0],
                    expkey[4 * i + 3][1],
                    expkey[4 * i + 3][2],
                    expkey[4 * i + 3][3],
                ],
            }
        }

        key
    }
}

