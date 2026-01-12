use sha2::{Sha256, Digest};

pub const POSEIDON_WIDTH: usize = 3;
pub const POSEIDON_RATE: usize = 2;

pub struct PoseidonHasher {
    state: [u64; POSEIDON_WIDTH],
}

impl PoseidonHasher {
    pub fn new() -> Self {
        Self {
            state: [0u64; POSEIDON_WIDTH],
        }
    }

    pub fn update(&mut self, input: &[u8]) {
        let mut hasher = Sha256::new();
        hasher.update(&self.state[0].to_le_bytes());
        hasher.update(&self.state[1].to_le_bytes());
        hasher.update(&self.state[2].to_le_bytes());
        hasher.update(input);
        
        let hash: [u8; 32] = hasher.finalize().into();
        
        self.state[0] = u64::from_le_bytes(hash[0..8].try_into().unwrap());
        self.state[1] = u64::from_le_bytes(hash[8..16].try_into().unwrap());
        self.state[2] = u64::from_le_bytes(hash[16..24].try_into().unwrap());
    }

    pub fn finalize(self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(&self.state[0].to_le_bytes());
        hasher.update(&self.state[1].to_le_bytes());
        hasher.update(&self.state[2].to_le_bytes());
        hasher.finalize().into()
    }
}

impl Default for PoseidonHasher {
    fn default() -> Self {
        Self::new()
    }
}

pub fn poseidon_hash(inputs: &[&[u8]]) -> [u8; 32] {
    let mut hasher = PoseidonHasher::new();
    for input in inputs {
        hasher.update(input);
    }
    hasher.finalize()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_poseidon_hash_deterministic() {
        let input1 = [1u8; 32];
        let input2 = [2u8; 32];
        
        let hash1 = poseidon_hash(&[&input1, &input2]);
        let hash2 = poseidon_hash(&[&input1, &input2]);
        
        assert_eq!(hash1, hash2);
    }

    #[test]
    fn test_poseidon_hash_different_inputs() {
        let input1 = [1u8; 32];
        let input2 = [2u8; 32];
        let input3 = [3u8; 32];
        
        let hash1 = poseidon_hash(&[&input1, &input2]);
        let hash2 = poseidon_hash(&[&input1, &input3]);
        
        assert_ne!(hash1, hash2);
    }
}
