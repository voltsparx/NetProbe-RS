// Blackrock-inspired permutation iterator for deterministic, memory-light target shuffling.

#[derive(Debug, Clone)]
pub struct BlackrockPermutation {
    size: u64,
    index: u64,
    half_bits: u32,
    half_mask: u64,
    domain_mask: u64,
    round_keys: [u64; 4],
}

impl BlackrockPermutation {
    pub fn new(size: usize, seed: u64) -> Self {
        let size_u64 = size as u64;
        let total_bits = permutation_bits(size_u64);
        let half_bits = total_bits / 2;
        let half_mask = bit_mask(half_bits);
        let domain_mask = bit_mask(total_bits);
        Self {
            size: size_u64,
            index: 0,
            half_bits,
            half_mask,
            domain_mask,
            round_keys: derive_round_keys(seed),
        }
    }

    #[cfg(test)]
    pub fn len(&self) -> usize {
        self.size as usize
    }

    pub fn at(&self, index: usize) -> usize {
        if self.size <= 1 {
            return 0;
        }

        let mut candidate = index as u64;
        loop {
            candidate = self.feistel(candidate);
            if candidate < self.size {
                return candidate as usize;
            }
        }
    }

    fn feistel(&self, value: u64) -> u64 {
        let mut left = (value >> self.half_bits) & self.half_mask;
        let mut right = value & self.half_mask;

        for (round, key) in self.round_keys.iter().copied().enumerate() {
            let mix = round_function(right, key, round as u64) & self.half_mask;
            let next = left ^ mix;
            left = right;
            right = next;
        }

        ((left << self.half_bits) | right) & self.domain_mask
    }
}

impl Iterator for BlackrockPermutation {
    type Item = usize;

    fn next(&mut self) -> Option<Self::Item> {
        if self.index >= self.size {
            return None;
        }

        let mapped = self.at(self.index as usize);
        self.index += 1;
        Some(mapped)
    }
}

fn scramble64(mut value: u64) -> u64 {
    value ^= value >> 33;
    value = value.wrapping_mul(0xff51_afd7_ed55_8ccd);
    value ^= value >> 33;
    value = value.wrapping_mul(0xc4ce_b9fe_1a85_ec53);
    value ^= value >> 33;
    value
}

fn derive_round_keys(seed: u64) -> [u64; 4] {
    [
        scramble64(seed ^ 0x517c_c1b7_2722_0a95),
        scramble64(seed ^ 0x9e37_79b9_7f4a_7c15),
        scramble64(seed ^ 0xd1b5_4a32_d192_ed03),
        scramble64(seed ^ 0x94d0_49bb_1331_11eb),
    ]
}

fn round_function(value: u64, key: u64, round: u64) -> u64 {
    let mixed = value
        .wrapping_mul(0x9e37_79b9_7f4a_7c15)
        .rotate_left(((round * 7 + 11) & 63) as u32)
        ^ key
        ^ round.wrapping_mul(0x517c_c1b7_2722_0a95);
    scramble64(mixed)
}

fn permutation_bits(size: u64) -> u32 {
    if size <= 1 {
        return 2;
    }

    let mut bits = 64 - (size - 1).leading_zeros();
    if bits % 2 != 0 {
        bits += 1;
    }
    bits.max(2)
}

fn bit_mask(bits: u32) -> u64 {
    if bits >= 64 {
        u64::MAX
    } else {
        (1u64 << bits) - 1
    }
}

#[cfg(test)]
mod tests {
    use super::BlackrockPermutation;

    #[test]
    fn permutation_is_deterministic() {
        let a: Vec<usize> = BlackrockPermutation::new(64, 0x1234).collect();
        let b: Vec<usize> = BlackrockPermutation::new(64, 0x1234).collect();
        assert_eq!(a, b);
    }

    #[test]
    fn permutation_covers_every_index_once() {
        let mut order: Vec<usize> = BlackrockPermutation::new(257, 42).collect();
        order.sort_unstable();
        let expected: Vec<usize> = (0..257).collect();
        assert_eq!(order, expected);
    }

    #[test]
    fn direct_index_mapping_matches_iterator() {
        let permutation = BlackrockPermutation::new(129, 9);
        let iter_values: Vec<usize> = permutation.clone().collect();
        let indexed_values: Vec<usize> = (0..permutation.len())
            .map(|idx| permutation.at(idx))
            .collect();
        assert_eq!(iter_values, indexed_values);
    }

    #[test]
    fn permutation_handles_non_power_of_two_domain() {
        let mut order: Vec<usize> = BlackrockPermutation::new(513, 0xfeed_beef).collect();
        order.sort_unstable();
        let expected: Vec<usize> = (0..513).collect();
        assert_eq!(order, expected);
    }
}
