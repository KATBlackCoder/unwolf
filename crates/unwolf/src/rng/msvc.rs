/// The Microsoft CRT `rand()` linear congruential generator.
///
/// Wolf RPG games are built with MSVC, so every `srand`/`rand` call in the
/// original code must use this generator, never the platform libc one.
#[derive(Debug, Clone)]
pub struct MsvcRand {
    state: u32,
}

impl MsvcRand {
    /// Equivalent of `srand(seed)`.
    pub fn new(seed: u32) -> Self {
        Self { state: seed }
    }

    /// Equivalent of `rand()`: a value in `0..=0x7FFF`.
    pub fn next_u32(&mut self) -> u32 {
        self.state = self.state.wrapping_mul(214_013).wrapping_add(2_531_011);
        (self.state >> 16) & 0x7FFF
    }
}

impl Default for MsvcRand {
    /// The CRT starts as if `srand(1)` had been called.
    fn default() -> Self {
        Self::new(1)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matches_known_msvc_sequence() {
        // Well-known MSVC output for the default seed 1.
        let mut r = MsvcRand::default();
        let got: Vec<u32> = (0..5).map(|_| r.next_u32()).collect();
        assert_eq!(got, [41, 18467, 6334, 26500, 19169]);
    }
}
