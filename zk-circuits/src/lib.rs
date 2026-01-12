mod poseidon;
mod merkle;
mod withdrawal_circuit;

pub use poseidon::{PoseidonChip, PoseidonConfig, poseidon_hash_native};
pub use merkle::{MerkleTree, MerkleProof, merkle_hash};
pub use withdrawal_circuit::{WithdrawalCircuit, WithdrawalConfig};

use halo2_proofs::{
    halo2curves::bn256::{Bn256, Fr, G1Affine},
    plonk::{keygen_pk, keygen_vk, create_proof, verify_proof, ProvingKey, VerifyingKey},
    poly::kzg::{
        commitment::{KZGCommitmentScheme, ParamsKZG},
        multiopen::{ProverSHPLONK, VerifierSHPLONK},
        strategy::SingleStrategy,
    },
    transcript::{Blake2bRead, Blake2bWrite, Challenge255, TranscriptReadBuffer, TranscriptWriterBuffer},
};
use rand::rngs::OsRng;
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

pub struct ProverParams {
    pub params: ParamsKZG<Bn256>,
    pub pk: ProvingKey<G1Affine>,
}

pub struct VerifierParams {
    pub params: ParamsKZG<Bn256>,
    pub vk: VerifyingKey<G1Affine>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Proof {
    pub bytes: Vec<u8>,
    pub public_inputs: Vec<[u8; 32]>,
}

impl Proof {
    pub fn to_bytes(&self) -> Vec<u8> {
        serde_json::to_vec(self).unwrap_or_default()
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, CircuitError> {
        serde_json::from_slice(bytes)
            .map_err(|e| CircuitError::Serialization(e.to_string()))
    }
}

pub fn setup_withdrawal_circuit(k: u32) -> Result<(ProverParams, VerifierParams), CircuitError> {
    let params = ParamsKZG::<Bn256>::setup(k, OsRng);
    let circuit = WithdrawalCircuit::<Fr>::default();
    
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
    circuit: WithdrawalCircuit<Fr>,
    public_inputs: &[&[Fr]],
) -> Result<Proof, CircuitError> {
    let mut transcript = Blake2bWrite::<_, G1Affine, Challenge255<_>>::init(vec![]);
    
    create_proof::<KZGCommitmentScheme<Bn256>, ProverSHPLONK<'_, Bn256>, _, _, _, _>(
        &prover.params,
        &prover.pk,
        &[circuit],
        &[public_inputs],
        OsRng,
        &mut transcript,
    )
    .map_err(|e| CircuitError::ProofGeneration(format!("Proof creation failed: {:?}", e)))?;
    
    let proof_bytes = transcript.finalize();
    
    let pi_bytes: Vec<[u8; 32]> = public_inputs.iter()
        .flat_map(|arr| arr.iter())
        .map(|fr| fr.to_bytes())
        .collect();
    
    Ok(Proof {
        bytes: proof_bytes,
        public_inputs: pi_bytes,
    })
}

pub fn verify_withdrawal(
    verifier: &VerifierParams,
    proof: &Proof,
    public_inputs: &[&[Fr]],
) -> Result<bool, CircuitError> {
    let mut transcript = Blake2bRead::<_, G1Affine, Challenge255<_>>::init(&proof.bytes[..]);
    
    let strategy = SingleStrategy::new(&verifier.params);
    
    verify_proof::<KZGCommitmentScheme<Bn256>, VerifierSHPLONK<'_, Bn256>, _, _, _>(
        &verifier.params,
        &verifier.vk,
        strategy,
        &[public_inputs],
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
            public_inputs: vec![[42u8; 32]],
        };
        
        let serialized = proof.to_bytes();
        let deserialized = Proof::from_bytes(&serialized).unwrap();
        
        assert_eq!(proof.bytes, deserialized.bytes);
        assert_eq!(proof.public_inputs, deserialized.public_inputs);
    }
}
