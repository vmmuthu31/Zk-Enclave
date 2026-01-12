mod poseidon;
mod merkle;
mod withdrawal_circuit;
mod association_circuit;

pub use poseidon::{PoseidonChip, PoseidonConfig, PoseidonSpec};
pub use merkle::{MerkleTreeChip, MerkleTreeConfig, MerkleProof};
pub use withdrawal_circuit::{WithdrawalCircuit, WithdrawalPublicInputs};
pub use association_circuit::{AssociationCircuit, AssociationPublicInputs};

use halo2_proofs::{
    plonk::{keygen_pk, keygen_vk, create_proof, verify_proof, ProvingKey, VerifyingKey},
    poly::kzg::{
        commitment::{KZGCommitmentScheme, ParamsKZG},
        multiopen::{ProverSHPLONK, VerifierSHPLONK},
        strategy::SingleStrategy,
    },
    transcript::{Blake2bRead, Blake2bWrite, Challenge255},
};
use halo2curves::bn256::{Bn256, Fr, G1Affine};
use rand::rngs::OsRng;
use thiserror::Error;

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

pub struct ProverParams {
    pub params: ParamsKZG<Bn256>,
    pub pk: ProvingKey<G1Affine>,
}

pub struct VerifierParams {
    pub params: ParamsKZG<Bn256>,
    pub vk: VerifyingKey<G1Affine>,
}

pub struct Proof {
    pub bytes: Vec<u8>,
    pub public_inputs: Vec<Fr>,
}

impl Proof {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut result = Vec::new();
        let pi_len = self.public_inputs.len() as u32;
        result.extend_from_slice(&pi_len.to_le_bytes());
        for pi in &self.public_inputs {
            result.extend_from_slice(&pi.to_bytes());
        }
        let proof_len = self.bytes.len() as u32;
        result.extend_from_slice(&proof_len.to_le_bytes());
        result.extend_from_slice(&self.bytes);
        result
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, CircuitError> {
        let mut cursor = 0;
        
        if bytes.len() < 4 {
            return Err(CircuitError::Serialization("Buffer too short".into()));
        }
        
        let pi_len = u32::from_le_bytes(bytes[cursor..cursor+4].try_into().unwrap()) as usize;
        cursor += 4;
        
        let mut public_inputs = Vec::with_capacity(pi_len);
        for _ in 0..pi_len {
            if cursor + 32 > bytes.len() {
                return Err(CircuitError::Serialization("Invalid public input".into()));
            }
            let mut pi_bytes = [0u8; 32];
            pi_bytes.copy_from_slice(&bytes[cursor..cursor+32]);
            public_inputs.push(Fr::from_bytes(&pi_bytes).unwrap());
            cursor += 32;
        }
        
        if cursor + 4 > bytes.len() {
            return Err(CircuitError::Serialization("Missing proof length".into()));
        }
        let proof_len = u32::from_le_bytes(bytes[cursor..cursor+4].try_into().unwrap()) as usize;
        cursor += 4;
        
        if cursor + proof_len > bytes.len() {
            return Err(CircuitError::Serialization("Incomplete proof data".into()));
        }
        let proof_bytes = bytes[cursor..cursor+proof_len].to_vec();
        
        Ok(Self {
            bytes: proof_bytes,
            public_inputs,
        })
    }
}

pub fn setup_withdrawal_circuit(k: u32) -> Result<(ProverParams, VerifierParams), CircuitError> {
    let params = ParamsKZG::<Bn256>::setup(k, OsRng);
    let circuit = WithdrawalCircuit::default();
    
    let vk = keygen_vk(&params, &circuit)
        .map_err(|e| CircuitError::ProofGeneration(format!("VK generation failed: {:?}", e)))?;
    let pk = keygen_pk(&params, vk.clone(), &circuit)
        .map_err(|e| CircuitError::ProofGeneration(format!("PK generation failed: {:?}", e)))?;
    
    Ok((
        ProverParams { params: params.clone(), pk },
        VerifierParams { params, vk },
    ))
}

pub fn prove_withdrawal(
    prover: &ProverParams,
    circuit: WithdrawalCircuit,
    public_inputs: &[Fr],
) -> Result<Proof, CircuitError> {
    let mut transcript = Blake2bWrite::<_, G1Affine, Challenge255<_>>::init(vec![]);
    
    create_proof::<KZGCommitmentScheme<Bn256>, ProverSHPLONK<Bn256>, _, _, _>(
        &prover.params,
        &prover.pk,
        &[circuit],
        &[&[public_inputs]],
        OsRng,
        &mut transcript,
    )
    .map_err(|e| CircuitError::ProofGeneration(format!("Proof creation failed: {:?}", e)))?;
    
    let proof_bytes = transcript.finalize();
    
    Ok(Proof {
        bytes: proof_bytes,
        public_inputs: public_inputs.to_vec(),
    })
}

pub fn verify_withdrawal(
    verifier: &VerifierParams,
    proof: &Proof,
) -> Result<bool, CircuitError> {
    let mut transcript = Blake2bRead::<_, G1Affine, Challenge255<_>>::init(&proof.bytes[..]);
    
    let strategy = SingleStrategy::new(&verifier.params);
    
    verify_proof::<KZGCommitmentScheme<Bn256>, VerifierSHPLONK<Bn256>, _, _>(
        &verifier.params,
        &verifier.vk,
        strategy,
        &[&[&proof.public_inputs]],
        &mut transcript,
    )
    .map_err(|e| CircuitError::ProofVerification(format!("Verification failed: {:?}", e)))?;
    
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_proof_serialization() {
        let proof = Proof {
            bytes: vec![1, 2, 3, 4, 5],
            public_inputs: vec![Fr::from(42u64), Fr::from(100u64)],
        };
        
        let serialized = proof.to_bytes();
        let deserialized = Proof::from_bytes(&serialized).unwrap();
        
        assert_eq!(proof.bytes, deserialized.bytes);
        assert_eq!(proof.public_inputs.len(), deserialized.public_inputs.len());
    }
}
