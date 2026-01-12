mod poseidon;
mod merkle;

pub use poseidon::{poseidon_hash, PoseidonHasher};
pub use merkle::{MerkleTree, MerkleProof};

use sha2::{Sha256, Digest};
use thiserror::Error;
use serde::{Serialize, Deserialize};

#[derive(Error, Debug)]
pub enum CircuitError {
    #[error("Proof generation failed: {0}")]
    ProofGeneration(String),
    #[error("Proof verification failed: {0}")]
    ProofVerification(String),
    #[error("Invalid input: {0}")]
    InvalidInput(String),
    #[error("Serialization error: {0}")]
    Serialization(String),
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WithdrawalPublicInputs {
    pub merkle_root: [u8; 32],
    pub nullifier: [u8; 32],
    pub recipient: [u8; 20],
    pub amount: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WithdrawalWitness {
    pub secret: [u8; 32],
    pub nullifier_seed: [u8; 32],
    pub merkle_path: Vec<[u8; 32]>,
    pub path_indices: Vec<bool>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Proof {
    pub bytes: Vec<u8>,
    pub public_inputs_hash: [u8; 32],
}

impl Proof {
    pub fn generate_withdrawal(
        witness: &WithdrawalWitness,
        public_inputs: &WithdrawalPublicInputs,
    ) -> Result<Self, CircuitError> {
        let commitment = poseidon_hash(&[
            &witness.secret,
            &witness.nullifier_seed,
        ]);

        let merkle_tree = MerkleTree::new(20);
        let computed_root = merkle_tree.compute_root_from_path(
            &commitment,
            &witness.merkle_path,
            &witness.path_indices,
        );

        if computed_root != public_inputs.merkle_root {
            return Err(CircuitError::ProofGeneration(
                "Merkle root mismatch".into()
            ));
        }

        let leaf_index = path_indices_to_index(&witness.path_indices);
        let nullifier = poseidon_hash(&[
            &witness.nullifier_seed,
            &leaf_index.to_le_bytes(),
        ]);

        if nullifier != public_inputs.nullifier {
            return Err(CircuitError::ProofGeneration(
                "Nullifier mismatch".into()
            ));
        }

        let mut hasher = Sha256::new();
        hasher.update(&public_inputs.merkle_root);
        hasher.update(&public_inputs.nullifier);
        hasher.update(&public_inputs.recipient);
        hasher.update(&public_inputs.amount.to_le_bytes());
        hasher.update(&commitment);
        let public_inputs_hash: [u8; 32] = hasher.finalize().into();

        let mut proof_data = Vec::new();
        proof_data.push(0x01);
        proof_data.extend_from_slice(&public_inputs_hash);
        proof_data.extend_from_slice(&public_inputs.merkle_root);
        proof_data.extend_from_slice(&public_inputs.nullifier);
        
        let mut sig_hasher = Sha256::new();
        sig_hasher.update(&proof_data);
        sig_hasher.update(&commitment);
        let signature: [u8; 32] = sig_hasher.finalize().into();
        proof_data.extend_from_slice(&signature);

        Ok(Self {
            bytes: proof_data,
            public_inputs_hash,
        })
    }

    pub fn verify_withdrawal(
        &self,
        public_inputs: &WithdrawalPublicInputs,
    ) -> Result<bool, CircuitError> {
        if self.bytes.len() < 97 {
            return Err(CircuitError::ProofVerification(
                "Proof too short".into()
            ));
        }

        if self.bytes[0] != 0x01 {
            return Err(CircuitError::ProofVerification(
                "Invalid proof version".into()
            ));
        }

        let proof_merkle_root = &self.bytes[33..65];
        if proof_merkle_root != public_inputs.merkle_root {
            return Ok(false);
        }

        let proof_nullifier = &self.bytes[65..97];
        if proof_nullifier != public_inputs.nullifier {
            return Ok(false);
        }

        let mut hasher = Sha256::new();
        hasher.update(&public_inputs.merkle_root);
        hasher.update(&public_inputs.nullifier);
        hasher.update(&public_inputs.recipient);
        hasher.update(&public_inputs.amount.to_le_bytes());
        
        Ok(true)
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        serde_json::to_vec(self).unwrap_or_default()
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, CircuitError> {
        serde_json::from_slice(bytes)
            .map_err(|e| CircuitError::Serialization(e.to_string()))
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AssociationPublicInputs {
    pub deposit_root: [u8; 32],
    pub association_root: [u8; 32],
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AssociationWitness {
    pub commitment: [u8; 32],
    pub deposit_path: Vec<[u8; 32]>,
    pub deposit_indices: Vec<bool>,
    pub association_path: Vec<[u8; 32]>,
    pub association_indices: Vec<bool>,
}

impl Proof {
    pub fn generate_association(
        witness: &AssociationWitness,
        public_inputs: &AssociationPublicInputs,
    ) -> Result<Self, CircuitError> {
        let merkle_tree = MerkleTree::new(20);
        
        let deposit_root = merkle_tree.compute_root_from_path(
            &witness.commitment,
            &witness.deposit_path,
            &witness.deposit_indices,
        );
        
        if deposit_root != public_inputs.deposit_root {
            return Err(CircuitError::ProofGeneration(
                "Deposit root mismatch".into()
            ));
        }

        let association_root = merkle_tree.compute_root_from_path(
            &witness.commitment,
            &witness.association_path,
            &witness.association_indices,
        );

        if association_root != public_inputs.association_root {
            return Err(CircuitError::ProofGeneration(
                "Association root mismatch".into()
            ));
        }

        let mut hasher = Sha256::new();
        hasher.update(&public_inputs.deposit_root);
        hasher.update(&public_inputs.association_root);
        let public_inputs_hash: [u8; 32] = hasher.finalize().into();

        let mut proof_data = Vec::new();
        proof_data.push(0x02);
        proof_data.extend_from_slice(&public_inputs_hash);
        proof_data.extend_from_slice(&public_inputs.deposit_root);
        proof_data.extend_from_slice(&public_inputs.association_root);

        Ok(Self {
            bytes: proof_data,
            public_inputs_hash,
        })
    }

    pub fn verify_association(
        &self,
        public_inputs: &AssociationPublicInputs,
    ) -> Result<bool, CircuitError> {
        if self.bytes.len() < 97 {
            return Err(CircuitError::ProofVerification(
                "Proof too short".into()
            ));
        }

        if self.bytes[0] != 0x02 {
            return Err(CircuitError::ProofVerification(
                "Invalid proof version".into()
            ));
        }

        let proof_deposit_root = &self.bytes[33..65];
        if proof_deposit_root != public_inputs.deposit_root {
            return Ok(false);
        }

        let proof_association_root = &self.bytes[65..97];
        if proof_association_root != public_inputs.association_root {
            return Ok(false);
        }

        Ok(true)
    }
}

fn path_indices_to_index(indices: &[bool]) -> u64 {
    let mut index = 0u64;
    for (i, &is_right) in indices.iter().enumerate() {
        if is_right {
            index |= 1 << i;
        }
    }
    index
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_proof_serialization() {
        let proof = Proof {
            bytes: vec![1, 2, 3, 4, 5],
            public_inputs_hash: [42u8; 32],
        };
        
        let serialized = proof.to_bytes();
        let deserialized = Proof::from_bytes(&serialized).unwrap();
        
        assert_eq!(proof.bytes, deserialized.bytes);
        assert_eq!(proof.public_inputs_hash, deserialized.public_inputs_hash);
    }

    #[test]
    fn test_withdrawal_proof_roundtrip() {
        let merkle_tree = MerkleTree::new(20);
        
        let secret = [1u8; 32];
        let nullifier_seed = [2u8; 32];
        let commitment = poseidon_hash(&[&secret, &nullifier_seed]);
        
        let (path, indices) = merkle_tree.generate_proof_for_leaf(&commitment, 0);
        let root = merkle_tree.compute_root_from_path(&commitment, &path, &indices);
        
        let leaf_index = path_indices_to_index(&indices);
        let nullifier = poseidon_hash(&[&nullifier_seed, &leaf_index.to_le_bytes()]);
        
        let witness = WithdrawalWitness {
            secret,
            nullifier_seed,
            merkle_path: path,
            path_indices: indices,
        };
        
        let public_inputs = WithdrawalPublicInputs {
            merkle_root: root,
            nullifier,
            recipient: [0xab; 20],
            amount: 1000000000000000000,
        };
        
        let proof = Proof::generate_withdrawal(&witness, &public_inputs).unwrap();
        assert!(proof.verify_withdrawal(&public_inputs).unwrap());
    }
}
