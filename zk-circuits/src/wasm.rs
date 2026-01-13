use wasm_bindgen::prelude::*;
use serde::{Serialize, Deserialize};
use halo2_proofs::{
    halo2curves::bn256::{Bn256, Fr, G1Affine},
    plonk::{keygen_pk, keygen_vk, create_proof, verify_proof, Circuit, ProvingKey},
    poly::{
        commitment::Params,
        kzg::{
            commitment::{KZGCommitmentScheme, ParamsKZG},
            multiopen::{ProverSHPLONK, VerifierSHPLONK},
            strategy::SingleStrategy,
        },
    },
    transcript::{Blake2bRead, Blake2bWrite, Challenge255, TranscriptReadBuffer, TranscriptWriterBuffer},
    SerdeFormat,
};
use rand::rngs::OsRng;
use sha2::{Sha256, Digest};
use std::sync::OnceLock;

use crate::withdrawal_circuit::{WithdrawalCircuit, WithdrawalWitness, WithdrawalPublicInputs, MERKLE_DEPTH};
use crate::association_circuit::{AssociationCircuit, AssociationWitness, AssociationPublicInputs, ASSOCIATION_DEPTH};

static PARAMS: OnceLock<ParamsKZG<Bn256>> = OnceLock::new();
static PK: OnceLock<ProvingKey<G1Affine>> = OnceLock::new();
static ASSOC_PK: OnceLock<ProvingKey<G1Affine>> = OnceLock::new();

const PARAMS_BYTES: &[u8] = include_bytes!("params.bin");
const PK_BYTES: &[u8] = include_bytes!("withdrawal_pk.bin");
const ASSOC_PK_BYTES: &[u8] = include_bytes!("association_pk.bin");

const K: u32 = 13; 

#[wasm_bindgen(start)]
pub fn init() {
    #[cfg(feature = "console_error_panic_hook")]
    console_error_panic_hook::set_once();
}

fn get_params() -> &'static ParamsKZG<Bn256> {
    PARAMS.get_or_init(|| {
        ParamsKZG::<Bn256>::read(&mut &PARAMS_BYTES[..]).expect("Failed to read params")
    })
}

fn get_pk() -> &'static ProvingKey<G1Affine> {
    PK.get_or_init(|| {
        ProvingKey::<G1Affine>::read::<_, WithdrawalCircuit<Fr>>(
            &mut &PK_BYTES[..],
            SerdeFormat::RawBytes
        ).expect("Failed to read PK")
    })
}

fn get_assoc_pk() -> &'static ProvingKey<G1Affine> {
    ASSOC_PK.get_or_init(|| {
        ProvingKey::<G1Affine>::read::<_, AssociationCircuit<Fr>>(
            &mut &ASSOC_PK_BYTES[..],
            SerdeFormat::RawBytes
        ).expect("Failed to read Association PK")
    })
}

#[derive(Serialize, Deserialize)]
pub struct ProofRequest {
    pub secret: Vec<u8>,
    pub nullifier_seed: Vec<u8>,
    pub amount: u64,
    pub leaf_index: u32,
    pub merkle_path: Vec<Vec<u8>>,
    pub path_indices: Vec<bool>,
    pub merkle_root: Vec<u8>,
    pub recipient: Vec<u8>,
}

#[derive(Serialize, Deserialize)]
pub struct ComplianceRequest {
    pub commitment: Vec<u8>,
    pub association_path: Vec<Vec<u8>>,
    pub path_indices: Vec<bool>,
    pub association_root: Vec<u8>,
}

#[derive(Serialize, Deserialize)]
pub struct ProofResult {
    pub success: bool,
    pub proof: Vec<u8>,
    pub nullifier_hash: Vec<u8>,
    pub public_inputs: Vec<Vec<u8>>,
    pub error: Option<String>,
}

#[derive(Serialize, Deserialize)]
pub struct ComplianceResult {
    pub success: bool,
    pub proof: Vec<u8>,
    pub public_inputs: Vec<Vec<u8>>,
    pub error: Option<String>,
}

#[wasm_bindgen]
pub fn generate_withdrawal_proof(request_json: &str) -> String {
    let request: ProofRequest = match serde_json::from_str(request_json) {
        Ok(r) => r,
        Err(e) => {
            return error_result(format!("Parse error: {}", e));
        }
    };

    let mut secret = [0u8; 32];
    let mut nullifier_seed = [0u8; 32];
    let mut merkle_root = [0u8; 32];
    let mut recipient = [0u8; 20];

    copy_bytes(&request.secret, &mut secret);
    copy_bytes(&request.nullifier_seed, &mut nullifier_seed);
    copy_bytes(&request.merkle_root, &mut merkle_root);
    copy_bytes_20(&request.recipient, &mut recipient);

    let merkle_path: Vec<[u8; 32]> = request.merkle_path
        .iter()
        .map(|p| {
            let mut arr = [0u8; 32];
            copy_bytes(p, &mut arr);
            arr
        })
        .collect();

    let mut path_indices = request.path_indices.clone();
    while path_indices.len() < MERKLE_DEPTH {
        path_indices.push(false);
    }

    let nullifier_hash = compute_nullifier(&nullifier_seed, request.leaf_index);

    let witness = WithdrawalWitness {
        secret,
        nullifier_seed,
        amount: request.amount,
        leaf_index: request.leaf_index,
        merkle_path: pad_merkle_path(merkle_path),
        path_indices,
    };

    let public_inputs = WithdrawalPublicInputs {
        merkle_root,
        nullifier: nullifier_hash,
        recipient,
        amount: request.amount,
    };

    let circuit = WithdrawalCircuit::<Fr>::new(witness, public_inputs.clone());

    match generate_real_proof(circuit) {
        Ok(proof_bytes) => {
             serde_json::to_string(&ProofResult {
                success: true,
                proof: proof_bytes,
                nullifier_hash: nullifier_hash.to_vec(),
                public_inputs: vec![
                    public_inputs.merkle_root.to_vec(),
                    public_inputs.nullifier.to_vec(),
                    public_inputs.recipient.to_vec(),
                ],
                error: None,
            }).unwrap()
        }
        Err(e) => error_result(e),
    }
}

#[wasm_bindgen]
pub fn generate_compliance_proof(request_json: &str) -> String {
    let request: ComplianceRequest = match serde_json::from_str(request_json) {
        Ok(r) => r,
        Err(e) => {
            return serde_json::to_string(&ComplianceResult {
                success: false,
                proof: vec![],
                public_inputs: vec![],
                error: Some(format!("Parse error: {}", e)),
            }).unwrap();
        }
    };

    let mut commitment = [0u8; 32];
    let mut association_root = [0u8; 32];

    copy_bytes(&request.commitment, &mut commitment);
    copy_bytes(&request.association_root, &mut association_root);

    let association_path: Vec<[u8; 32]> = request.association_path
        .iter()
        .map(|p| {
            let mut arr = [0u8; 32];
            copy_bytes(p, &mut arr);
            arr
        })
        .collect();

    let mut path_indices = request.path_indices.clone();
    while path_indices.len() < ASSOCIATION_DEPTH {
        path_indices.push(false);
    }

    let params = get_params();
    let pk = get_assoc_pk();

    let witness = AssociationWitness {
        commitment,
        association_path: pad_association_path(association_path),
        path_indices,
    };

    let public_inputs = AssociationPublicInputs {
        association_root,
        commitment_hash: commitment, 
    };

    let circuit = AssociationCircuit::<Fr>::new(witness, public_inputs.clone());

    let mut transcript = Blake2bWrite::<_, G1Affine, Challenge255<_>>::init(vec![]);
    
    match create_proof::<KZGCommitmentScheme<Bn256>, ProverSHPLONK<'_, Bn256>, _, _, _, _>(
        params,
        pk,
        &[circuit],
        &[&[]], 
        OsRng,
        &mut transcript,
    ) {
        Ok(_) => {
            let proof = transcript.finalize();
             serde_json::to_string(&ComplianceResult {
                success: true,
                proof,
                public_inputs: vec![
                    public_inputs.association_root.to_vec(),
                    public_inputs.commitment_hash.to_vec(),
                ],
                error: None,
            }).unwrap()
        },
        Err(e) => serde_json::to_string(&ComplianceResult {
            success: false,
            proof: vec![],
            public_inputs: vec![],
            error: Some(format!("Proof generation failed: {:?}", e)),
        }).unwrap()
    }
}

fn generate_real_proof(circuit: WithdrawalCircuit<Fr>) -> Result<Vec<u8>, String> {
    let params = get_params();
    let pk = get_pk();

    let mut transcript = Blake2bWrite::<_, G1Affine, Challenge255<_>>::init(vec![]);
    
    create_proof::<KZGCommitmentScheme<Bn256>, ProverSHPLONK<'_, Bn256>, _, _, _, _>(
        params,
        pk,
        &[circuit],
        &[&[]],
        OsRng,
        &mut transcript,
    ).map_err(|e| format!("create_proof failed: {:?}", e))?;

    let proof = transcript.finalize();
    Ok(proof)
}

#[wasm_bindgen]
pub fn verify_withdrawal_proof(proof_json: &str) -> bool {
    let result: Result<ProofResult, _> = serde_json::from_str(proof_json);
    match result {
        Ok(r) => {
            if !r.success || r.proof.is_empty() {
                return false;
            }
            
            let params = get_params();
            let empty_circuit = WithdrawalCircuit::<Fr>::default();
            
            let vk = match keygen_vk(params, &empty_circuit) {
                Ok(vk) => vk,
                Err(_) => return false,
            };

            let mut transcript = Blake2bRead::<_, G1Affine, Challenge255<_>>::init(&r.proof[..]);
            
            verify_proof::<KZGCommitmentScheme<Bn256>, VerifierSHPLONK<'_, Bn256>, _, _, _>(
                params,
                &vk,
                SingleStrategy::new(params),
                &[&[]],
                &mut transcript,
            ).is_ok()
        }
        Err(_) => false,
    }
}

fn compute_nullifier(seed: &[u8; 32], leaf_index: u32) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(seed);
    hasher.update(&leaf_index.to_le_bytes());
    let result = hasher.finalize();
    let mut output = [0u8; 32];
    output.copy_from_slice(&result);
    output
}

fn copy_bytes(src: &[u8], dst: &mut [u8; 32]) {
    let len = src.len().min(32);
    dst[..len].copy_from_slice(&src[..len]);
}

fn copy_bytes_20(src: &[u8], dst: &mut [u8; 20]) {
    let len = src.len().min(20);
    dst[..len].copy_from_slice(&src[..len]);
}

fn pad_merkle_path(mut path: Vec<[u8; 32]>) -> Vec<[u8; 32]> {
    while path.len() < MERKLE_DEPTH {
        path.push([0u8; 32]);
    }
    path
}

fn pad_association_path(mut path: Vec<[u8; 32]>) -> Vec<[u8; 32]> {
    while path.len() < ASSOCIATION_DEPTH {
        path.push([0u8; 32]);
    }
    path
}

fn error_result(msg: String) -> String {
    serde_json::to_string(&ProofResult {
        success: false,
        proof: vec![],
        nullifier_hash: vec![],
        public_inputs: vec![],
        error: Some(msg),
    }).unwrap()
}
