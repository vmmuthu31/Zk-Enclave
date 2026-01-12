use alloc::vec::Vec;
use scale::{Decode, Encode};
use sha2::{Sha256, Digest};

use crate::Error;

#[derive(Debug, Clone, Default, Encode, Decode)]
pub struct EncryptedState {
    contract_key: [u8; 32],
    state_version: u32,
    commitment_count: u64,
    last_update: u64,
}

impl EncryptedState {
    pub fn new() -> Self {
        let mut key = [0u8; 32];
        
        let seed = [
            0x6b, 0x65, 0x79, 0x5f, 0x73, 0x65, 0x65, 0x64,
            0x5f, 0x66, 0x6f, 0x72, 0x5f, 0x74, 0x65, 0x73,
            0x74, 0x69, 0x6e, 0x67, 0x5f, 0x6f, 0x6e, 0x6c,
            0x79, 0x5f, 0x76, 0x31, 0x2e, 0x30, 0x2e, 0x30,
        ];
        
        let mut hasher = Sha256::new();
        hasher.update(&seed);
        key.copy_from_slice(&hasher.finalize());
        
        Self {
            contract_key: key,
            state_version: 1,
            commitment_count: 0,
            last_update: 0,
        }
    }

    pub fn encrypt(&self) -> Result<Vec<u8>, Error> {
        let encoded = self.encode();
        
        let mut encrypted = Vec::with_capacity(encoded.len() + 4);
        encrypted.extend_from_slice(&[0xE0, 0x01, 0x00, 0x00]); // Magic + version
        
        for (i, byte) in encoded.iter().enumerate() {
            encrypted.push(byte ^ self.contract_key[i % 32]);
        }
        
        Ok(encrypted)
    }

    pub fn decrypt(encrypted: &[u8]) -> Result<Self, Error> {
        if encrypted.len() < 4 {
            return Err(Error::DecryptionError);
        }
        
        if encrypted[0] != 0xE0 || encrypted[1] != 0x01 {
            return Err(Error::DecryptionError);
        }
        
        let temp_state = Self::new();
        
        let mut decrypted = Vec::with_capacity(encrypted.len() - 4);
        for (i, byte) in encrypted[4..].iter().enumerate() {
            decrypted.push(byte ^ temp_state.contract_key[i % 32]);
        }
        
        Self::decode(&mut &decrypted[..])
            .map_err(|_| Error::DecryptionError)
    }

    pub fn increment_commitment_count(&mut self) {
        self.commitment_count += 1;
    }

    pub fn update_timestamp(&mut self, timestamp: u64) {
        self.last_update = timestamp;
    }

    pub fn get_contract_key(&self) -> &[u8; 32] {
        &self.contract_key
    }

    pub fn get_commitment_count(&self) -> u64 {
        self.commitment_count
    }
}

#[derive(Debug, Clone, Default, Encode, Decode)]
pub struct NullifierSet {
    nullifiers: Vec<[u8; 32]>,
    bloom_filter: [u64; 16],
}

impl NullifierSet {
    pub fn new() -> Self {
        Self {
            nullifiers: Vec::new(),
            bloom_filter: [0u64; 16],
        }
    }

    pub fn insert(&mut self, nullifier: [u8; 32]) -> bool {
        if self.contains(&nullifier) {
            return false;
        }
        
        self.add_to_bloom(&nullifier);
        self.nullifiers.push(nullifier);
        true
    }

    pub fn contains(&self, nullifier: &[u8; 32]) -> bool {
        if !self.check_bloom(nullifier) {
            return false;
        }
        
        self.nullifiers.contains(nullifier)
    }

    fn add_to_bloom(&mut self, nullifier: &[u8; 32]) {
        let indices = self.bloom_indices(nullifier);
        for (word_idx, bit_idx) in indices {
            self.bloom_filter[word_idx] |= 1u64 << bit_idx;
        }
    }

    fn check_bloom(&self, nullifier: &[u8; 32]) -> bool {
        let indices = self.bloom_indices(nullifier);
        for (word_idx, bit_idx) in indices {
            if self.bloom_filter[word_idx] & (1u64 << bit_idx) == 0 {
                return false;
            }
        }
        true
    }

    fn bloom_indices(&self, nullifier: &[u8; 32]) -> [(usize, usize); 3] {
        let h1 = u64::from_le_bytes(nullifier[0..8].try_into().unwrap());
        let h2 = u64::from_le_bytes(nullifier[8..16].try_into().unwrap());
        let h3 = u64::from_le_bytes(nullifier[16..24].try_into().unwrap());
        
        [
            ((h1 as usize) % 16, (h1 >> 4) as usize % 64),
            ((h2 as usize) % 16, (h2 >> 4) as usize % 64),
            ((h3 as usize) % 16, (h3 >> 4) as usize % 64),
        ]
    }

    pub fn len(&self) -> usize {
        self.nullifiers.len()
    }

    pub fn is_empty(&self) -> bool {
        self.nullifiers.is_empty()
    }
}

#[derive(Debug, Clone, Encode, Decode)]
pub struct AuditTrail {
    entries: Vec<AuditEntryInternal>,
    merkle_root: [u8; 32],
    entry_count: u64,
}

#[derive(Debug, Clone, Encode, Decode)]
struct AuditEntryInternal {
    timestamp: u64,
    commitment_hash: [u8; 32],
    operation_type: u8,
    encrypted_metadata: Vec<u8>,
}

impl AuditTrail {
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
            merkle_root: [0u8; 32],
            entry_count: 0,
        }
    }

    pub fn log_withdrawal(
        &mut self,
        timestamp: u64,
        commitment: [u8; 32],
        metadata: Vec<u8>,
    ) {
        let mut hasher = Sha256::new();
        hasher.update(&commitment);
        let commitment_hash: [u8; 32] = hasher.finalize().into();
        
        let entry = AuditEntryInternal {
            timestamp,
            commitment_hash,
            operation_type: 1, // Withdrawal
            encrypted_metadata: metadata,
        };
        
        self.entries.push(entry);
        self.entry_count += 1;
        self.update_merkle_root();
    }

    fn update_merkle_root(&mut self) {
        if self.entries.is_empty() {
            self.merkle_root = [0u8; 32];
            return;
        }
        
        let mut hasher = Sha256::new();
        for entry in &self.entries {
            hasher.update(&entry.commitment_hash);
        }
        self.merkle_root = hasher.finalize().into();
    }

    pub fn get_merkle_root(&self) -> [u8; 32] {
        self.merkle_root
    }

    pub fn get_entry_count(&self) -> u64 {
        self.entry_count
    }

    pub fn generate_inclusion_proof(&self, index: usize) -> Option<Vec<[u8; 32]>> {
        if index >= self.entries.len() {
            return None;
        }
        
        Some(vec![self.merkle_root])
    }
}

impl Default for AuditTrail {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encrypted_state_roundtrip() {
        let state = EncryptedState::new();
        let encrypted = state.encrypt().unwrap();
        let decrypted = EncryptedState::decrypt(&encrypted).unwrap();
        
        assert_eq!(state.state_version, decrypted.state_version);
        assert_eq!(state.commitment_count, decrypted.commitment_count);
    }

    #[test]
    fn test_nullifier_set() {
        let mut set = NullifierSet::new();
        
        let n1 = [1u8; 32];
        let n2 = [2u8; 32];
        
        assert!(!set.contains(&n1));
        assert!(set.insert(n1));
        assert!(set.contains(&n1));
        assert!(!set.insert(n1)); // Duplicate
        
        assert!(!set.contains(&n2));
        assert!(set.insert(n2));
        assert!(set.contains(&n2));
        
        assert_eq!(set.len(), 2);
    }

    #[test]
    fn test_audit_trail() {
        let mut trail = AuditTrail::new();
        
        assert_eq!(trail.get_entry_count(), 0);
        
        trail.log_withdrawal(1000, [1u8; 32], vec![0, 1, 2]);
        assert_eq!(trail.get_entry_count(), 1);
        
        trail.log_withdrawal(2000, [2u8; 32], vec![3, 4, 5]);
        assert_eq!(trail.get_entry_count(), 2);
        
        assert_ne!(trail.get_merkle_root(), [0u8; 32]);
    }
}
