// Blackrock-inspired permutation iterator for deterministic, memory-light target shuffling.

#[derive(Debug, Clone)]
pub struct BlackrockPermutation {
    size: u64,
    index: u64,
    multiplier: u64,
    offset: u64,
}

impl BlackrockPermutation {
    pub fn new(size: usize, seed: u64) -> Self {
        let size_u64 = size as u64;
        let multiplier = choose_coprime_multiplier(size_u64, seed);
        let offset = if size_u64 <= 1 {
            0
        } else {
            scramble64(seed ^ 0x9e37_79b9_7f4a_7c15) % size_u64
        };
        Self {
            size: size_u64,
            index: 0,
            multiplier,
            offset,
        }
    }
}

impl Iterator for BlackrockPermutation {
    type Item = usize;

    fn next(&mut self) -> Option<Self::Item> {
        if self.index >= self.size {
            return None;
        }

        let mapped = if self.size <= 1 {
            0
        } else {
            (self
                .multiplier
                .wrapping_mul(self.index)
                .wrapping_add(self.offset))
                % self.size
        };
        self.index += 1;
        Some(mapped as usize)
    }
}

fn choose_coprime_multiplier(size: u64, seed: u64) -> u64 {
    if size <= 1 {
        return 1;
    }

    let mut candidate = (scramble64(seed) | 1) % size;
    if candidate == 0 {
        candidate = 1;
    }

    while gcd(candidate, size) != 1 {
        candidate = (candidate + 2) % size;
        if candidate == 0 {
            candidate = 1;
        }
    }
    candidate
}

fn gcd(mut left: u64, mut right: u64) -> u64 {
    while right != 0 {
        let next = left % right;
        left = right;
        right = next;
    }
    left
}

fn scramble64(mut value: u64) -> u64 {
    value ^= value >> 33;
    value = value.wrapping_mul(0xff51_afd7_ed55_8ccd);
    value ^= value >> 33;
    value = value.wrapping_mul(0xc4ce_b9fe_1a85_ec53);
    value ^= value >> 33;
    value
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
}
