use alloc::vec::Vec;
use scale::{Decode, Encode};
use sha2::{Sha256, Digest};

use crate::{Error, WithdrawalRequest};

pub struct WithdrawalProcessor {
    commitment_root: [u8; 32],
    vault_address: [u8; 20],
}

impl WithdrawalProcessor {
    pub fn new(commitment_root: [u8; 32], vault_address: [u8; 20]) -> Self {
        Self {
            commitment_root,
            vault_address,
        }
    }

    pub fn generate_withdrawal_proof(
        &self,
        request: &WithdrawalRequest,
    ) -> Result<(Vec<u8>, bool), Error> {
        self.validate_request(request)?;

        let is_valid = self.verify_merkle_inclusion(
            &request.commitment,
            &request.merkle_proof,
            &request.proof_indices,
        )?;

        if !is_valid {
            return Err(Error::InvalidMerkleProof);
        }

        let nullifier_valid = self.verify_nullifier_derivation(
            &request.commitment,
            &request.nullifier,
        );

        if !nullifier_valid {
            return Err(Error::InvalidProof);
        }

        let proof = self.generate_zk_proof(request)?;

        Ok((proof, true))
    }

    fn validate_request(&self, request: &WithdrawalRequest) -> Result<(), Error> {
        if request.amount == 0 {
            return Err(Error::InvalidRequest);
        }

        if request.merkle_proof.is_empty() {
            return Err(Error::InvalidMerkleProof);
        }

        if request.merkle_proof.len() != request.proof_indices.len() {
            return Err(Error::InvalidMerkleProof);
        }

        Ok(())
    }

    fn verify_merkle_inclusion(
        &self,
        leaf: &[u8; 32],
        proof: &[[u8; 32]],
        indices: &[bool],
    ) -> Result<bool, Error> {
        let mut current = *leaf;

        for (sibling, is_right) in proof.iter().zip(indices.iter()) {
            current = if *is_right {
                self.hash_pair(sibling, &current)
            } else {
                self.hash_pair(&current, sibling)
            };
        }

        Ok(current == self.commitment_root)
    }

    fn hash_pair(&self, left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(left);
        hasher.update(right);
        hasher.finalize().into()
    }

    fn verify_nullifier_derivation(
        &self,
        commitment: &[u8; 32],
        nullifier: &[u8; 32],
    ) -> bool {
        let mut hasher = Sha256::new();
        hasher.update(b"nullifier");
        hasher.update(commitment);
        let expected: [u8; 32] = hasher.finalize().into();
        
        &expected[..16] == &nullifier[..16]
    }

    fn generate_zk_proof(&self, request: &WithdrawalRequest) -> Result<Vec<u8>, Error> {
        let proof_data = ZKProofData {
            commitment: request.commitment,
            nullifier: request.nullifier,
            recipient: request.recipient,
            amount: request.amount,
            merkle_root: self.commitment_root,
            vault_address: self.vault_address,
        };

        let mut hasher = Sha256::new();
        hasher.update(&proof_data.commitment);
        hasher.update(&proof_data.nullifier);
        hasher.update(&proof_data.recipient);
        hasher.update(&proof_data.amount.to_le_bytes());
        hasher.update(&proof_data.merkle_root);
        
        let proof_hash: [u8; 32] = hasher.finalize().into();

        let mut proof = Vec::with_capacity(256);
        proof.extend_from_slice(&[0x01]); // Version byte
        proof.extend_from_slice(&proof_hash);
        proof.extend_from_slice(&proof_data.merkle_root);
        proof.extend_from_slice(&proof_data.nullifier);
        proof.extend_from_slice(&[0u8; 159]); // Padding to 256 bytes
        
        Ok(proof)
    }

    pub fn verify_association_set(
        &self,
        commitment: &[u8; 32],
        association_root: &[u8; 32],
        association_proof: &[[u8; 32]],
        proof_indices: &[bool],
    ) -> Result<bool, Error> {
        let mut current = *commitment;

        for (sibling, is_right) in association_proof.iter().zip(proof_indices.iter()) {
            current = if *is_right {
                self.hash_pair(sibling, &current)
            } else {
                self.hash_pair(&current, sibling)
            };
        }

        Ok(current == *association_root)
    }
}

#[derive(Debug, Clone, Encode, Decode)]
struct ZKProofData {
    commitment: [u8; 32],
    nullifier: [u8; 32],
    recipient: [u8; 20],
    amount: u128,
    merkle_root: [u8; 32],
    vault_address: [u8; 20],
}

pub struct BatchProcessor {
    requests: Vec<WithdrawalRequest>,
    max_batch_size: usize,
}

impl BatchProcessor {
    pub fn new(max_batch_size: usize) -> Self {
        Self {
            requests: Vec::new(),
            max_batch_size,
        }
    }

    pub fn add_request(&mut self, request: WithdrawalRequest) -> Result<bool, Error> {
        if self.requests.len() >= self.max_batch_size {
            return Ok(true); // Batch is full
        }
        
        self.requests.push(request);
        Ok(false)
    }

    pub fn process_batch(
        &mut self,
        commitment_root: [u8; 32],
        vault_address: [u8; 20],
    ) -> Result<Vec<(Vec<u8>, [u8; 32])>, Error> {
        let processor = WithdrawalProcessor::new(commitment_root, vault_address);
        
        let mut results = Vec::with_capacity(self.requests.len());
        
        for request in &self.requests {
            let (proof, valid) = processor.generate_withdrawal_proof(request)?;
            if valid {
                results.push((proof, request.nullifier));
            }
        }
        
        self.requests.clear();
        
        Ok(results)
    }

    pub fn pending_count(&self) -> usize {
        self.requests.len()
    }

    pub fn is_full(&self) -> bool {
        self.requests.len() >= self.max_batch_size
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_request() -> WithdrawalRequest {
        WithdrawalRequest {
            commitment: [1u8; 32],
            nullifier: [2u8; 32],
            recipient: [3u8; 20],
            amount: 1000000,
            merkle_proof: vec![[4u8; 32], [5u8; 32]],
            proof_indices: vec![false, true],
        }
    }

    #[test]
    fn test_processor_creation() {
        let processor = WithdrawalProcessor::new([0u8; 32], [0u8; 20]);
        assert_eq!(processor.commitment_root, [0u8; 32]);
    }

    #[test]
    fn test_hash_pair() {
        let processor = WithdrawalProcessor::new([0u8; 32], [0u8; 20]);
        let left = [1u8; 32];
        let right = [2u8; 32];
        
        let hash1 = processor.hash_pair(&left, &right);
        let hash2 = processor.hash_pair(&left, &right);
        assert_eq!(hash1, hash2);
        
        let hash3 = processor.hash_pair(&right, &left);
        assert_ne!(hash1, hash3);
    }

    #[test]
    fn test_batch_processor() {
        let mut batch = BatchProcessor::new(3);
        
        assert_eq!(batch.pending_count(), 0);
        assert!(!batch.is_full());
        
        let request = create_test_request();
        batch.add_request(request.clone()).unwrap();
        
        assert_eq!(batch.pending_count(), 1);
        assert!(!batch.is_full());
        
        batch.add_request(request.clone()).unwrap();
        batch.add_request(request.clone()).unwrap();
        
        assert_eq!(batch.pending_count(), 3);
        assert!(batch.is_full());
    }
}
