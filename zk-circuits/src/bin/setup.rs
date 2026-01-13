use std::fs::File;
use std::io::Write;
use halo2_proofs::{
    halo2curves::bn256::{Bn256, Fr},
    plonk::{keygen_pk, keygen_vk, ProvingKey, VerifyingKey},
    poly::{
        commitment::Params,
        kzg::{
            commitment::{KZGCommitmentScheme, ParamsKZG},
        },
    },
    SerdeFormat,
};
use zkenclave_circuits::{
    withdrawal_circuit::{WithdrawalCircuit, WithdrawalPublicInputs, WithdrawalWitness},
};
use rand::rngs::OsRng;

fn main() {
    let k = 13;
    
    println!("1. Generating Params for K={}...", k);
    let params = ParamsKZG::<Bn256>::setup(k, OsRng);
    
    let mut params_file = File::create("src/params.bin").unwrap();
    params.write(&mut params_file).unwrap();
    println!("   Saved src/params.bin");

    println!("2. Generating Keys...");
    let witness = WithdrawalWitness::default(); 
    let public_inputs = WithdrawalPublicInputs::default();
    let circuit = WithdrawalCircuit::<Fr>::new(witness, public_inputs);
    
    let vk = keygen_vk(&params, &circuit).expect("keygen_vk failed");
    let pk = keygen_pk(&params, vk.clone(), &circuit).expect("keygen_pk failed");

    let mut vk_file = File::create("src/withdrawal_vk.bin").unwrap();
    vk.write(&mut vk_file, SerdeFormat::RawBytes).unwrap();
    
    let mut pk_file = File::create("src/withdrawal_pk.bin").unwrap();
    pk.write(&mut pk_file, SerdeFormat::RawBytes).unwrap();
    
    println!("   Saved src/withdrawal_vk.bin and src/withdrawal_pk.bin");

    println!("2b. Generating Association Keys...");
    let assoc_witness = zkenclave_circuits::association_circuit::AssociationWitness::default();
    let assoc_pub = zkenclave_circuits::association_circuit::AssociationPublicInputs::default();
    let assoc_circuit = zkenclave_circuits::association_circuit::AssociationCircuit::<Fr>::new(assoc_witness, assoc_pub);

    let assoc_vk = keygen_vk(&params, &assoc_circuit).expect("assoc keygen_vk failed");
    let assoc_pk = keygen_pk(&params, assoc_vk.clone(), &assoc_circuit).expect("assoc keygen_pk failed");

    let mut assoc_vk_file = File::create("src/association_vk.bin").unwrap();
    assoc_vk.write(&mut assoc_vk_file, SerdeFormat::RawBytes).unwrap();

    let mut assoc_pk_file = File::create("src/association_pk.bin").unwrap();
    assoc_pk.write(&mut assoc_pk_file, SerdeFormat::RawBytes).unwrap();
    println!("   Saved src/association_vk.bin and src/association_pk.bin");
    
    println!("3. Generating Solidity Verifier (Skipped - requires template)...");
    println!("Done!");
}
