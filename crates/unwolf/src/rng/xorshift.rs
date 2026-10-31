/// The `xorshift32` generator from UberWolf's `WolfCrypt.hpp`.
///
/// The original keeps the state in a function-local static; seeding with a
/// non-zero value replaces the state and also performs one step. Here
/// [`Xorshift32::new`] only sets the state: call [`Xorshift32::next_u32`]
/// once to reproduce the seeding call.
#[derive(Debug, Clone)]
pub struct Xorshift32 {
    state: u32,
}

impl Xorshift32 {
    pub fn new(seed: u32) -> Self {
        Self { state: seed }
    }

    pub fn next_u32(&mut self) -> u32 {
        let mut s = self.state;
        s ^= s << 11;
        s ^= s >> 19;
        s ^= s << 7;
        self.state = s;
        s
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn steps_like_the_original() {
        let mut x = Xorshift32::new(1);
        // 1 ^ (1 << 11) = 0x801; ^ (>> 19) = 0x801; ^ (<< 7) = 0x40881
        assert_eq!(x.next_u32(), 0x0004_0881);
    }
}
