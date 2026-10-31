//! The custom generator chain used to derive AES keys for Wolf RPG Pro data
//! (`WolfRng.hpp` and `aesKeyGen` in UberWolfLib).

use super::MsvcRand;

const OUTER_LEN: usize = 0x20;
const INNER_LEN: usize = 0x100;
/// Number of bytes produced by [`aes_key_gen`] before the shuffle.
pub const DATA_LEN: usize = 0x30;

/// State shared by the three custom generators.
#[derive(Clone)]
pub struct RngData {
    seed1: u32,
    seed2: u32,
    counter: u32,
    data: Box<[[u32; INNER_LEN]; OUTER_LEN]>,
}

impl Default for RngData {
    fn default() -> Self {
        Self {
            seed1: 0,
            seed2: 0,
            counter: 0,
            data: Box::new([[0; INNER_LEN]; OUTER_LEN]),
        }
    }
}

impl RngData {
    fn rng1(&mut self) -> u32 {
        let s1 = self.seed1;
        let seed_p1 = s1 ^ (((s1 << 11) ^ s1) >> 8);
        let seed = (s1 << 11) ^ seed_p1;
        let mut state = seed.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
        let modv = if (13u32.wrapping_mul(seed_p1).wrapping_add(95) & 1) == 0 {
            state / 8
        } else {
            state.wrapping_mul(4)
        };
        state ^= modv;
        let modv = if state & 0x400 != 0 {
            state ^= state << 21;
            state >> 9
        } else {
            state ^= state.wrapping_mul(4);
            state >> 22
        };
        state ^= modv;
        if state & 0xFFFFF == 0 {
            state = state.wrapping_add(256);
        }
        self.seed1 = state;
        state
    }

    fn rng2(&mut self) -> u32 {
        let seed = self.seed1;
        let mut state = seed.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
        let shift = (seed & 7) + 1;
        match state % 3 {
            0 => state ^= state << shift,
            1 => state ^= state >> shift,
            _ => state = (!state).wrapping_add(state << shift),
        }
        if state != 0 {
            if state as u16 == 0 {
                state ^= 0x55AA_55AA;
            }
        } else {
            state = 0x0017_3BEF;
        }
        self.seed1 = state;
        state
    }

    fn rng3(&mut self) -> u32 {
        let seed = self.seed2;
        let mut state = seed.wrapping_mul(1_566_083_941) ^ seed.wrapping_mul(292_331_520);
        state ^= (state >> 17) ^ (state ^ (state >> 17)).wrapping_mul(32);
        // C precedence: `a ^ b & c` is `a ^ (b & c)`.
        state = 69_069u32.wrapping_mul(state ^ ((state ^ (state >> 11)) & 0x3FFF_FFFF));
        if state != 0 {
            if state as u16 == 0 {
                state ^= 0x59A6_F141;
            }
            if state & 0xFFFFF == 0 {
                state = state.wrapping_add(256);
            }
        } else {
            state = 1_566_083_941;
        }
        self.seed2 = state;
        state
    }

    /// `rngChain`: refill one row of the table.
    fn chain(&mut self, row: &mut [u32; INNER_LEN]) {
        for (i, d) in row.iter_mut().enumerate() {
            let rn = self.rng2();
            *d = rn ^ self.rng3();
            self.counter = self.counter.wrapping_add(1);
            if self.counter & 1 == 0 {
                *d = d.wrapping_add(self.rng3());
            }
            let c = self.counter;
            if c % 3 == 0 {
                *d ^= self.rng1().wrapping_add(3);
            }
            if c % 7 == 0 {
                *d = d.wrapping_add(self.rng3().wrapping_add(1));
            }
            if c & 7 == 0 {
                *d = d.wrapping_mul(self.rng1());
            }
            if (i as u32).wrapping_add(self.seed1) % 5 == 0 {
                *d ^= self.rng1();
            }
            if c % 9 == 0 {
                *d = d.wrapping_add(self.rng2().wrapping_add(4));
            }
            if c % 0x18 == 0 {
                *d = d.wrapping_add(self.rng2().wrapping_add(7));
            }
            if c % 0x1F == 0 {
                *d = d.wrapping_add(self.rng3().wrapping_mul(3));
            }
            if c % 0x3D == 0 {
                *d = d.wrapping_add(self.rng3().wrapping_add(1));
            }
            if c % 0xA1 == 0 {
                *d = d.wrapping_add(self.rng2());
            }
            if rn as u16 == 256 {
                *d = d.wrapping_add(self.rng3().wrapping_mul(3));
            }
        }
    }

    fn chain_row(&mut self, idx: usize) {
        let mut row = self.data[idx];
        self.chain(&mut row);
        self.data[idx] = row;
    }

    /// `runRngChain`: reseed and refill the whole table.
    pub fn run_chain(&mut self, seed1: u32, seed2: u32) {
        self.seed1 = seed1;
        self.seed2 = seed2;
        self.counter = 0;
        for i in 0..OUTER_LEN {
            self.chain_row(i);
        }
    }

    /// `aLotOfRngStuff`.
    fn mix(&mut self, mut a2: u32, mut a3: u32, idx: usize, out: &mut [u8; DATA_LEN]) {
        let mut itrs = 20u32;
        let mut i = 0u32;
        while i < itrs {
            let idx1 = ((a2 ^ self.rng1()) & 0x1F) as usize;
            let idx2 = ((a3 ^ self.rng2()) & 0xFF) as usize;
            a3 = self.data[idx1][idx2];
            match a2.wrapping_add(self.counter) % 0x14 {
                1 => self.chain_row((a2.wrapping_add(5) & 0x1F) as usize),
                2 => a3 ^= self.rng1(),
                5 if a2 & 0xFFFFF == 0 => out[idx] ^= self.rng3() as u8,
                9 | 0xE => {
                    let j = (self.rng2() % DATA_LEN as u32) as usize;
                    out[j] = out[j].wrapping_add(a3 as u8);
                }
                0xB => out[idx] ^= self.rng1() as u8,
                0x11 => itrs += 1,
                0x13 if a2 as u16 == 0 => out[idx] ^= self.rng2() as u8,
                _ => {}
            }
            a2 = a2.wrapping_add(self.rng3());
            if itrs > 50 {
                itrs = 50;
            }
            i += 1;
        }
        out[idx] = out[idx].wrapping_add(a3 as u8);
    }
}

/// `aesKeyGen`: derive a 16-byte AES key and a 16-byte IV from four seed bytes.
pub fn aes_key_gen(seed_bytes: [u8; 4], rd: &mut RngData) -> ([u8; 16], [u8; 16]) {
    rd.run_chain(u32::from(seed_bytes[0]), u32::from(seed_bytes[1]));
    let mut data = [0u8; DATA_LEN];
    for i in 0..DATA_LEN as u32 {
        rd.mix(
            i.wrapping_add(u32::from(seed_bytes[3])),
            u32::from(seed_bytes[2]).wrapping_sub(i),
            i as usize,
            &mut data,
        );
    }

    let mut indexes: [u8; DATA_LEN] = std::array::from_fn(|i| i as u8);
    let mut rand = MsvcRand::new(u32::from(seed_bytes[1] ^ seed_bytes[2]));
    for i in 0..DATA_LEN {
        let j = (rand.next_u32() % DATA_LEN as u32) as usize;
        indexes.swap(i, j);
    }
    let shuffled: [u8; DATA_LEN] = std::array::from_fn(|i| data[indexes[i] as usize]);

    let mut key = [0u8; 16];
    let mut iv = [0u8; 16];
    key.copy_from_slice(&shuffled[..16]);
    iv.copy_from_slice(&shuffled[16..32]);
    (key, iv)
}
