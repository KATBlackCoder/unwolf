/// 32-bit Mersenne Twister, bit-identical to C++ `std::mt19937`.
#[derive(Clone)]
pub struct Mt19937 {
    mt: [u32; N],
    index: usize,
}

const N: usize = 624;
const M: usize = 397;
const MATRIX_A: u32 = 0x9908_B0DF;
const UPPER_MASK: u32 = 0x8000_0000;
const LOWER_MASK: u32 = 0x7FFF_FFFF;

impl Mt19937 {
    pub fn new(seed: u32) -> Self {
        let mut mt = [0u32; N];
        mt[0] = seed;
        for i in 1..N {
            let prev = mt[i - 1];
            mt[i] = 1_812_433_253u32
                .wrapping_mul(prev ^ (prev >> 30))
                .wrapping_add(i as u32);
        }
        Self { mt, index: N }
    }

    pub fn next_u32(&mut self) -> u32 {
        if self.index >= N {
            self.twist();
        }
        let mut y = self.mt[self.index];
        self.index += 1;
        y ^= y >> 11;
        y ^= (y << 7) & 0x9D2C_5680;
        y ^= (y << 15) & 0xEFC6_0000;
        y ^= y >> 18;
        y
    }

    fn twist(&mut self) {
        for i in 0..N {
            let y = (self.mt[i] & UPPER_MASK) | (self.mt[(i + 1) % N] & LOWER_MASK);
            let mut v = self.mt[(i + M) % N] ^ (y >> 1);
            if y & 1 != 0 {
                v ^= MATRIX_A;
            }
            self.mt[i] = v;
        }
        self.index = 0;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matches_cpp_standard_check_value() {
        // The C++ standard requires the 10000th output of a
        // default-constructed mt19937 (seed 5489) to be 4123659995.
        let mut mt = Mt19937::new(5489);
        let mut v = 0;
        for _ in 0..10_000 {
            v = mt.next_u32();
        }
        assert_eq!(v, 4_123_659_995);
    }
}
