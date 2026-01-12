use sha2::{Sha256, Digest};
use serde::{Serialize, Deserialize};
use std::collections::{HashMap, HashSet};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum ASPError {
    #[error("Commitment not found in set")]
    CommitmentNotFound,
    #[error("Commitment is excluded")]
    CommitmentExcluded,
    #[error("Invalid proof")]
    InvalidProof,
    #[error("Provider not initialized")]
    NotInitialized,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProviderConfig {
    pub name: String,
    pub policy_type: PolicyType,
    pub update_frequency_secs: u64,
    pub max_set_size: usize,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub enum PolicyType {
    Permissive,
    Restrictive,
    Custom(String),
}

impl Default for ProviderConfig {
    fn default() -> Self {
        Self {
            name: "Default ASP".into(),
            policy_type: PolicyType::Permissive,
            update_frequency_secs: 3600,
            max_set_size: 1_000_000,
        }
    }
}

pub struct AssociationSetProvider {
    config: ProviderConfig,
    approved_set: HashSet<[u8; 32]>,
    merkle_nodes: Vec<Vec<[u8; 32]>>,
    root: [u8; 32],
    exclusion_list: ExclusionList,
    last_update: u64,
    commitment_indices: HashMap<[u8; 32], usize>,
}

impl AssociationSetProvider {
    pub fn new(config: ProviderConfig) -> Self {
        Self {
            config,
            approved_set: HashSet::new(),
            merkle_nodes: vec![Vec::new()],
            root: [0u8; 32],
            exclusion_list: ExclusionList::new(),
            last_update: 0,
            commitment_indices: HashMap::new(),
        }
    }

    pub fn add_commitment(&mut self, commitment: [u8; 32]) -> Result<usize, ASPError> {
        if self.exclusion_list.is_excluded(&commitment) {
            return Err(ASPError::CommitmentExcluded);
        }

        if self.approved_set.len() >= self.config.max_set_size {
            return Err(ASPError::InvalidProof);
        }

        let index = self.approved_set.len();
        self.approved_set.insert(commitment);
        self.commitment_indices.insert(commitment, index);
        
        if self.merkle_nodes[0].len() <= index {
            self.merkle_nodes[0].push(commitment);
        } else {
            self.merkle_nodes[0][index] = commitment;
        }
        
        self.rebuild_merkle_tree();
        
        Ok(index)
    }

    pub fn remove_commitment(&mut self, commitment: &[u8; 32]) -> bool {
        if self.approved_set.remove(commitment) {
            self.commitment_indices.remove(commitment);
            self.rebuild_merkle_tree();
            true
        } else {
            false
        }
    }

    pub fn is_approved(&self, commitment: &[u8; 32]) -> bool {
        self.approved_set.contains(commitment) && !self.exclusion_list.is_excluded(commitment)
    }

    pub fn generate_proof(&self, commitment: &[u8; 32]) -> Result<MerkleProof, ASPError> {
        if !self.approved_set.contains(commitment) {
            return Err(ASPError::CommitmentNotFound);
        }
        
        if self.exclusion_list.is_excluded(commitment) {
            return Err(ASPError::CommitmentExcluded);
        }

        let index = *self.commitment_indices.get(commitment)
            .ok_or(ASPError::CommitmentNotFound)?;
        
        let mut path = Vec::new();
        let mut indices = Vec::new();
        let mut current_idx = index;

        for level in 0..self.merkle_nodes.len() - 1 {
            let is_right = current_idx % 2 == 1;
            let sibling_idx = if is_right { current_idx - 1 } else { current_idx + 1 };
            
            let sibling = if sibling_idx < self.merkle_nodes[level].len() {
                self.merkle_nodes[level][sibling_idx]
            } else {
                [0u8; 32]
            };
            
            path.push(sibling);
            indices.push(is_right);
            current_idx /= 2;
        }

        Ok(MerkleProof {
            path,
            indices,
            root: self.root,
        })
    }

    pub fn verify_proof(&self, commitment: &[u8; 32], proof: &MerkleProof) -> bool {
        let mut current = *commitment;

        for (sibling, is_right) in proof.path.iter().zip(proof.indices.iter()) {
            let (left, right) = if *is_right {
                (*sibling, current)
            } else {
                (current, *sibling)
            };
            current = hash_pair(&left, &right);
        }

        current == proof.root && proof.root == self.root
    }

    pub fn root(&self) -> [u8; 32] {
        self.root
    }

    pub fn size(&self) -> usize {
        self.approved_set.len()
    }

    pub fn config(&self) -> &ProviderConfig {
        &self.config
    }

    pub fn set_exclusion_list(&mut self, list: ExclusionList) {
        self.exclusion_list = list;
        self.rebuild_merkle_tree();
    }

    pub fn update_timestamp(&mut self, timestamp: u64) {
        self.last_update = timestamp;
    }

    fn rebuild_merkle_tree(&mut self) {
        if self.merkle_nodes[0].is_empty() {
            self.root = [0u8; 32];
            return;
        }

        let depth = (self.merkle_nodes[0].len() as f64).log2().ceil() as usize + 1;
        self.merkle_nodes = vec![self.merkle_nodes[0].clone()];
        
        let target_size = 1 << (depth - 1);
        while self.merkle_nodes[0].len() < target_size {
            self.merkle_nodes[0].push([0u8; 32]);
        }

        for level in 0..depth - 1 {
            let current_layer = &self.merkle_nodes[level];
            let mut next_layer = Vec::with_capacity((current_layer.len() + 1) / 2);

            for i in (0..current_layer.len()).step_by(2) {
                let left = current_layer[i];
                let right = if i + 1 < current_layer.len() {
                    current_layer[i + 1]
                } else {
                    [0u8; 32]
                };
                next_layer.push(hash_pair(&left, &right));
            }

            self.merkle_nodes.push(next_layer);
        }

        self.root = self.merkle_nodes.last()
            .and_then(|l| l.first().copied())
            .unwrap_or([0u8; 32]);
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MerkleProof {
    pub path: Vec<[u8; 32]>,
    pub indices: Vec<bool>,
    pub root: [u8; 32],
}

pub struct ExclusionList {
    addresses: HashSet<[u8; 32]>,
    patterns: Vec<ExclusionPattern>,
    source: String,
    last_update: u64,
}

#[derive(Clone, Debug)]
pub struct ExclusionPattern {
    pub pattern_type: PatternType,
    pub data: Vec<u8>,
}

#[derive(Clone, Debug)]
pub enum PatternType {
    ExactMatch,
    PrefixMatch,
    RegexMatch,
}

impl ExclusionList {
    pub fn new() -> Self {
        Self {
            addresses: HashSet::new(),
            patterns: Vec::new(),
            source: String::new(),
            last_update: 0,
        }
    }

    pub fn add_address(&mut self, address: [u8; 32]) {
        self.addresses.insert(address);
    }

    pub fn remove_address(&mut self, address: &[u8; 32]) {
        self.addresses.remove(address);
    }

    pub fn is_excluded(&self, commitment: &[u8; 32]) -> bool {
        if self.addresses.contains(commitment) {
            return true;
        }

        for pattern in &self.patterns {
            if self.matches_pattern(commitment, pattern) {
                return true;
            }
        }

        false
    }

    fn matches_pattern(&self, commitment: &[u8; 32], pattern: &ExclusionPattern) -> bool {
        match pattern.pattern_type {
            PatternType::ExactMatch => commitment[..] == pattern.data[..],
            PatternType::PrefixMatch => commitment.starts_with(&pattern.data),
            PatternType::RegexMatch => false,
        }
    }

    pub fn size(&self) -> usize {
        self.addresses.len()
    }

    pub fn set_source(&mut self, source: String) {
        self.source = source;
    }

    pub fn update_timestamp(&mut self, timestamp: u64) {
        self.last_update = timestamp;
    }
}

impl Default for ExclusionList {
    fn default() -> Self {
        Self::new()
    }
}

fn hash_pair(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(left);
    hasher.update(right);
    hasher.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_asp_basic_operations() {
        let config = ProviderConfig::default();
        let mut asp = AssociationSetProvider::new(config);

        let c1 = [1u8; 32];
        let c2 = [2u8; 32];
        let c3 = [3u8; 32];

        asp.add_commitment(c1).unwrap();
        asp.add_commitment(c2).unwrap();
        asp.add_commitment(c3).unwrap();

        assert!(asp.is_approved(&c1));
        assert!(asp.is_approved(&c2));
        assert!(asp.is_approved(&c3));
        assert!(!asp.is_approved(&[4u8; 32]));

        assert_eq!(asp.size(), 3);
        assert_ne!(asp.root(), [0u8; 32]);
    }

    #[test]
    fn test_merkle_proof_generation() {
        let config = ProviderConfig::default();
        let mut asp = AssociationSetProvider::new(config);

        for i in 0..10 {
            let mut commitment = [0u8; 32];
            commitment[0] = i;
            asp.add_commitment(commitment).unwrap();
        }

        let commitment = {
            let mut c = [0u8; 32];
            c[0] = 5;
            c
        };

        let proof = asp.generate_proof(&commitment).unwrap();
        assert!(asp.verify_proof(&commitment, &proof));
    }

    #[test]
    fn test_exclusion_list() {
        let mut exclusion = ExclusionList::new();
        let bad_address = [0xbau8; 32];

        exclusion.add_address(bad_address);
        assert!(exclusion.is_excluded(&bad_address));

        let config = ProviderConfig::default();
        let mut asp = AssociationSetProvider::new(config);
        asp.set_exclusion_list(exclusion);

        let result = asp.add_commitment(bad_address);
        assert!(result.is_err());
    }

    #[test]
    fn test_policy_types() {
        let permissive = PolicyType::Permissive;
        let restrictive = PolicyType::Restrictive;
        let custom = PolicyType::Custom("my-policy".into());

        assert_eq!(permissive, PolicyType::Permissive);
        assert_ne!(permissive, restrictive);
        
        if let PolicyType::Custom(name) = custom {
            assert_eq!(name, "my-policy");
        }
    }
}
