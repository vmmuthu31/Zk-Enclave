use sha2::{Sha256, Digest};
use serde::{Serialize, Deserialize};
use std::collections::HashMap;
use thiserror::Error;
use chrono::{DateTime, Utc};

#[derive(Error, Debug)]
pub enum AuditError {
    #[error("Entry not found")]
    EntryNotFound,
    #[error("Invalid disclosure key")]
    InvalidKey,
    #[error("Encryption error")]
    EncryptionError,
    #[error("Audit trail corrupted")]
    Corrupted,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AuditEntry {
    pub id: [u8; 32],
    pub timestamp: u64,
    pub operation_type: OperationType,
    pub commitment_hash: [u8; 32],
    pub encrypted_details: Vec<u8>,
    pub tee_attestation: Vec<u8>,
    pub merkle_index: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub enum OperationType {
    Deposit,
    Withdrawal,
    ComplianceCheck,
    ASPUpdate,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AuditDetails {
    pub commitment: [u8; 32],
    pub amount: Option<u128>,
    pub recipient_hash: Option<[u8; 32]>,
    pub asp_provider: Option<String>,
    pub compliance_result: Option<bool>,
    pub metadata: HashMap<String, String>,
}

pub struct AuditTrail {
    entries: Vec<AuditEntry>,
    merkle_root: [u8; 32],
    entry_count: u64,
    disclosure_keys: HashMap<[u8; 32], [u8; 32]>,
}

impl AuditTrail {
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
            merkle_root: [0u8; 32],
            entry_count: 0,
            disclosure_keys: HashMap::new(),
        }
    }

    pub fn log_withdrawal(
        &mut self,
        commitment: [u8; 32],
        amount: u128,
        recipient_hash: [u8; 32],
        tee_attestation: Vec<u8>,
    ) -> Result<[u8; 32], AuditError> {
        let details = AuditDetails {
            commitment,
            amount: Some(amount),
            recipient_hash: Some(recipient_hash),
            asp_provider: None,
            compliance_result: None,
            metadata: HashMap::new(),
        };

        self.log_entry(OperationType::Withdrawal, commitment, details, tee_attestation)
    }

    pub fn log_deposit(
        &mut self,
        commitment: [u8; 32],
        amount: u128,
        tee_attestation: Vec<u8>,
    ) -> Result<[u8; 32], AuditError> {
        let details = AuditDetails {
            commitment,
            amount: Some(amount),
            recipient_hash: None,
            asp_provider: None,
            compliance_result: None,
            metadata: HashMap::new(),
        };

        self.log_entry(OperationType::Deposit, commitment, details, tee_attestation)
    }

    pub fn log_compliance_check(
        &mut self,
        commitment: [u8; 32],
        asp_provider: String,
        result: bool,
        tee_attestation: Vec<u8>,
    ) -> Result<[u8; 32], AuditError> {
        let details = AuditDetails {
            commitment,
            amount: None,
            recipient_hash: None,
            asp_provider: Some(asp_provider),
            compliance_result: Some(result),
            metadata: HashMap::new(),
        };

        self.log_entry(OperationType::ComplianceCheck, commitment, details, tee_attestation)
    }

    fn log_entry(
        &mut self,
        operation_type: OperationType,
        commitment: [u8; 32],
        details: AuditDetails,
        tee_attestation: Vec<u8>,
    ) -> Result<[u8; 32], AuditError> {
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        let commitment_hash = hash_commitment(&commitment);
        
        let (encrypted_details, disclosure_key) = self.encrypt_details(&details)?;
        
        let entry_id = self.compute_entry_id(timestamp, &commitment_hash, self.entry_count);

        let entry = AuditEntry {
            id: entry_id,
            timestamp,
            operation_type,
            commitment_hash,
            encrypted_details,
            tee_attestation,
            merkle_index: self.entry_count,
        };

        self.entries.push(entry);
        self.disclosure_keys.insert(entry_id, disclosure_key);
        self.entry_count += 1;
        self.update_merkle_root();

        Ok(entry_id)
    }

    pub fn get_entry(&self, id: &[u8; 32]) -> Option<&AuditEntry> {
        self.entries.iter().find(|e| &e.id == id)
    }

    pub fn query(&self, query: &AuditQuery) -> Vec<&AuditEntry> {
        self.entries.iter()
            .filter(|e| self.matches_query(e, query))
            .collect()
    }

    pub fn generate_inclusion_proof(&self, entry_id: &[u8; 32]) -> Result<InclusionProof, AuditError> {
        let index = self.entries.iter()
            .position(|e| &e.id == entry_id)
            .ok_or(AuditError::EntryNotFound)?;

        let hashes: Vec<[u8; 32]> = self.entries.iter()
            .map(|e| self.hash_entry(e))
            .collect();

        let (path, indices) = self.compute_merkle_path(&hashes, index);

        Ok(InclusionProof {
            entry_hash: hashes[index],
            path,
            indices,
            root: self.merkle_root,
        })
    }

    pub fn verify_inclusion(&self, proof: &InclusionProof) -> bool {
        let mut current = proof.entry_hash;

        for (sibling, is_right) in proof.path.iter().zip(proof.indices.iter()) {
            let (left, right) = if *is_right {
                (*sibling, current)
            } else {
                (current, *sibling)
            };
            current = hash_pair(&left, &right);
        }

        current == proof.root && proof.root == self.merkle_root
    }

    pub fn selective_disclosure(
        &self,
        entry_id: &[u8; 32],
        regulator_key: &[u8; 32],
    ) -> Result<SelectiveDisclosure, AuditError> {
        let entry = self.get_entry(entry_id)
            .ok_or(AuditError::EntryNotFound)?;

        let disclosure_key = self.disclosure_keys.get(entry_id)
            .ok_or(AuditError::InvalidKey)?;

        let decrypted = self.decrypt_details(&entry.encrypted_details, disclosure_key)?;
        
        let reencrypted = self.encrypt_for_regulator(&decrypted, regulator_key)?;

        let proof = self.generate_inclusion_proof(entry_id)?;

        Ok(SelectiveDisclosure {
            entry_id: *entry_id,
            timestamp: entry.timestamp,
            operation_type: entry.operation_type.clone(),
            encrypted_for_regulator: reencrypted,
            inclusion_proof: proof,
            tee_attestation: entry.tee_attestation.clone(),
        })
    }

    pub fn merkle_root(&self) -> [u8; 32] {
        self.merkle_root
    }

    pub fn entry_count(&self) -> u64 {
        self.entry_count
    }

    fn encrypt_details(&self, details: &AuditDetails) -> Result<(Vec<u8>, [u8; 32]), AuditError> {
        let serialized = serde_json::to_vec(details)
            .map_err(|_| AuditError::EncryptionError)?;

        let mut key = [0u8; 32];
        let mut hasher = Sha256::new();
        hasher.update(&serialized);
        hasher.update(b"disclosure_key");
        key.copy_from_slice(&hasher.finalize());

        let encrypted: Vec<u8> = serialized.iter()
            .enumerate()
            .map(|(i, b)| b ^ key[i % 32])
            .collect();

        Ok((encrypted, key))
    }

    fn decrypt_details(&self, encrypted: &[u8], key: &[u8; 32]) -> Result<AuditDetails, AuditError> {
        let decrypted: Vec<u8> = encrypted.iter()
            .enumerate()
            .map(|(i, b)| b ^ key[i % 32])
            .collect();

        serde_json::from_slice(&decrypted)
            .map_err(|_| AuditError::EncryptionError)
    }

    fn encrypt_for_regulator(&self, details: &AuditDetails, regulator_key: &[u8; 32]) -> Result<Vec<u8>, AuditError> {
        let serialized = serde_json::to_vec(details)
            .map_err(|_| AuditError::EncryptionError)?;

        let encrypted: Vec<u8> = serialized.iter()
            .enumerate()
            .map(|(i, b)| b ^ regulator_key[i % 32])
            .collect();

        Ok(encrypted)
    }

    fn compute_entry_id(&self, timestamp: u64, commitment_hash: &[u8; 32], index: u64) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(&timestamp.to_le_bytes());
        hasher.update(commitment_hash);
        hasher.update(&index.to_le_bytes());
        hasher.finalize().into()
    }

    fn hash_entry(&self, entry: &AuditEntry) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(&entry.id);
        hasher.update(&entry.timestamp.to_le_bytes());
        hasher.update(&entry.commitment_hash);
        hasher.finalize().into()
    }

    fn update_merkle_root(&mut self) {
        if self.entries.is_empty() {
            self.merkle_root = [0u8; 32];
            return;
        }

        let hashes: Vec<[u8; 32]> = self.entries.iter()
            .map(|e| self.hash_entry(e))
            .collect();

        self.merkle_root = self.compute_merkle_root(&hashes);
    }

    fn compute_merkle_root(&self, leaves: &[[u8; 32]]) -> [u8; 32] {
        if leaves.is_empty() {
            return [0u8; 32];
        }
        if leaves.len() == 1 {
            return leaves[0];
        }

        let mut current_level = leaves.to_vec();
        while current_level.len() > 1 {
            let mut next_level = Vec::new();
            for i in (0..current_level.len()).step_by(2) {
                let left = current_level[i];
                let right = if i + 1 < current_level.len() {
                    current_level[i + 1]
                } else {
                    [0u8; 32]
                };
                next_level.push(hash_pair(&left, &right));
            }
            current_level = next_level;
        }

        current_level[0]
    }

    fn compute_merkle_path(&self, leaves: &[[u8; 32]], index: usize) -> (Vec<[u8; 32]>, Vec<bool>) {
        let mut path = Vec::new();
        let mut indices = Vec::new();
        let mut current_level = leaves.to_vec();
        let mut current_index = index;

        while current_level.len() > 1 {
            let is_right = current_index % 2 == 1;
            let sibling_index = if is_right { current_index - 1 } else { current_index + 1 };

            let sibling = if sibling_index < current_level.len() {
                current_level[sibling_index]
            } else {
                [0u8; 32]
            };

            path.push(sibling);
            indices.push(is_right);

            let mut next_level = Vec::new();
            for i in (0..current_level.len()).step_by(2) {
                let left = current_level[i];
                let right = if i + 1 < current_level.len() {
                    current_level[i + 1]
                } else {
                    [0u8; 32]
                };
                next_level.push(hash_pair(&left, &right));
            }

            current_level = next_level;
            current_index /= 2;
        }

        (path, indices)
    }

    fn matches_query(&self, entry: &AuditEntry, query: &AuditQuery) -> bool {
        if let Some(ref op_type) = query.operation_type {
            if &entry.operation_type != op_type {
                return false;
            }
        }

        if let Some(start) = query.start_time {
            if entry.timestamp < start {
                return false;
            }
        }

        if let Some(end) = query.end_time {
            if entry.timestamp > end {
                return false;
            }
        }

        if let Some(ref commitment) = query.commitment_hash {
            if &entry.commitment_hash != commitment {
                return false;
            }
        }

        true
    }
}

impl Default for AuditTrail {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Clone, Debug)]
pub struct AuditQuery {
    pub operation_type: Option<OperationType>,
    pub start_time: Option<u64>,
    pub end_time: Option<u64>,
    pub commitment_hash: Option<[u8; 32]>,
}

impl AuditQuery {
    pub fn new() -> Self {
        Self {
            operation_type: None,
            start_time: None,
            end_time: None,
            commitment_hash: None,
        }
    }

    pub fn with_operation(mut self, op: OperationType) -> Self {
        self.operation_type = Some(op);
        self
    }

    pub fn with_time_range(mut self, start: u64, end: u64) -> Self {
        self.start_time = Some(start);
        self.end_time = Some(end);
        self
    }

    pub fn with_commitment(mut self, commitment: [u8; 32]) -> Self {
        self.commitment_hash = Some(hash_commitment(&commitment));
        self
    }
}

impl Default for AuditQuery {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct InclusionProof {
    pub entry_hash: [u8; 32],
    pub path: Vec<[u8; 32]>,
    pub indices: Vec<bool>,
    pub root: [u8; 32],
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SelectiveDisclosure {
    pub entry_id: [u8; 32],
    pub timestamp: u64,
    pub operation_type: OperationType,
    pub encrypted_for_regulator: Vec<u8>,
    pub inclusion_proof: InclusionProof,
    pub tee_attestation: Vec<u8>,
}

fn hash_commitment(commitment: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(commitment);
    hasher.finalize().into()
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
    fn test_audit_trail_basic() {
        let mut trail = AuditTrail::new();

        let commitment = [1u8; 32];
        let amount = 1_000_000u128;
        let attestation = vec![0u8; 64];

        let entry_id = trail.log_deposit(commitment, amount, attestation.clone()).unwrap();
        
        assert_eq!(trail.entry_count(), 1);
        assert!(trail.get_entry(&entry_id).is_some());
    }

    #[test]
    fn test_inclusion_proof() {
        let mut trail = AuditTrail::new();

        for i in 0..5 {
            let mut commitment = [0u8; 32];
            commitment[0] = i;
            trail.log_deposit(commitment, 1000, vec![]).unwrap();
        }

        let target_id = {
            let mut commitment = [0u8; 32];
            commitment[0] = 2;
            trail.log_deposit(commitment, 500, vec![]).unwrap()
        };

        let proof = trail.generate_inclusion_proof(&target_id).unwrap();
        assert!(trail.verify_inclusion(&proof));
    }

    #[test]
    fn test_query() {
        let mut trail = AuditTrail::new();

        trail.log_deposit([1u8; 32], 1000, vec![]).unwrap();
        trail.log_withdrawal([2u8; 32], 500, [3u8; 32], vec![]).unwrap();
        trail.log_deposit([4u8; 32], 2000, vec![]).unwrap();

        let query = AuditQuery::new().with_operation(OperationType::Deposit);
        let results = trail.query(&query);
        
        assert_eq!(results.len(), 2);
    }

    #[test]
    fn test_selective_disclosure() {
        let mut trail = AuditTrail::new();

        let commitment = [1u8; 32];
        let entry_id = trail.log_deposit(commitment, 1000, vec![0u8; 32]).unwrap();

        let regulator_key = [0xabu8; 32];
        let disclosure = trail.selective_disclosure(&entry_id, &regulator_key).unwrap();

        assert_eq!(disclosure.entry_id, entry_id);
        assert!(trail.verify_inclusion(&disclosure.inclusion_proof));
    }
}
