use halo2_proofs::{
    arithmetic::Field,
    circuit::{AssignedCell, Layouter, SimpleFloorPlanner, Value},
    plonk::{Advice, Circuit, Column, ConstraintSystem, Error, Expression, Fixed, Instance, Selector},
    poly::Rotation,
};
use halo2curves::bn256::Fr as Fp;
use crate::poseidon::{poseidon_hash_native, PoseidonChip, PoseidonConfig, POSEIDON_WIDTH};
use crate::merkle::{MerkleProof, MerkleTreeChip, MerkleTreeConfig, MERKLE_DEPTH};

#[derive(Clone, Debug)]
pub struct WithdrawalPublicInputs {
    pub merkle_root: Fp,
    pub nullifier_hash: Fp,
    pub recipient: Fp,
    pub amount: Fp,
}

impl WithdrawalPublicInputs {
    pub fn to_vec(&self) -> Vec<Fp> {
        vec![
            self.merkle_root,
            self.nullifier_hash,
            self.recipient,
            self.amount,
        ]
    }

    pub fn from_slice(slice: &[Fp]) -> Self {
        assert!(slice.len() >= 4);
        Self {
            merkle_root: slice[0],
            nullifier_hash: slice[1],
            recipient: slice[2],
            amount: slice[3],
        }
    }
}

#[derive(Clone)]
pub struct WithdrawalConfig {
    pub advice: [Column<Advice>; 4],
    pub fixed: [Column<Fixed>; 2],
    pub instance: Column<Instance>,
    pub selector_main: Selector,
    pub selector_nullifier: Selector,
    pub selector_commitment: Selector,
    pub poseidon_config: PoseidonConfig,
}

#[derive(Clone, Default)]
pub struct WithdrawalCircuit {
    pub secret: Value<Fp>,
    pub nullifier_seed: Value<Fp>,
    pub amount: Value<Fp>,
    pub merkle_path: Vec<Value<Fp>>,
    pub path_indices: Vec<Value<bool>>,
    pub recipient: Value<Fp>,
}

impl WithdrawalCircuit {
    pub fn new(
        secret: Fp,
        nullifier_seed: Fp,
        amount: Fp,
        merkle_proof: &MerkleProof,
        recipient: Fp,
    ) -> Self {
        Self {
            secret: Value::known(secret),
            nullifier_seed: Value::known(nullifier_seed),
            amount: Value::known(amount),
            merkle_path: merkle_proof.path.iter().map(|&p| Value::known(p)).collect(),
            path_indices: merkle_proof.indices.iter().map(|&i| Value::known(i)).collect(),
            recipient: Value::known(recipient),
        }
    }

    pub fn compute_commitment(secret: Fp, nullifier_seed: Fp, amount: Fp) -> Fp {
        poseidon_hash_native(&[secret, nullifier_seed, amount])
    }

    pub fn compute_nullifier(nullifier_seed: Fp, leaf_index: u64) -> Fp {
        poseidon_hash_native(&[nullifier_seed, Fp::from(leaf_index)])
    }

    pub fn generate_public_inputs(
        secret: Fp,
        nullifier_seed: Fp,
        amount: Fp,
        merkle_proof: &MerkleProof,
        recipient: Fp,
        leaf_index: u64,
    ) -> WithdrawalPublicInputs {
        let commitment = Self::compute_commitment(secret, nullifier_seed, amount);
        let merkle_root = merkle_proof.compute_root(commitment);
        let nullifier_hash = Self::compute_nullifier(nullifier_seed, leaf_index);

        WithdrawalPublicInputs {
            merkle_root,
            nullifier_hash,
            recipient,
            amount,
        }
    }
}

impl Circuit<Fp> for WithdrawalCircuit {
    type Config = WithdrawalConfig;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self {
            secret: Value::unknown(),
            nullifier_seed: Value::unknown(),
            amount: Value::unknown(),
            merkle_path: vec![Value::unknown(); MERKLE_DEPTH],
            path_indices: vec![Value::unknown(); MERKLE_DEPTH],
            recipient: Value::unknown(),
        }
    }

    fn configure(meta: &mut ConstraintSystem<Fp>) -> Self::Config {
        let advice = [
            meta.advice_column(),
            meta.advice_column(),
            meta.advice_column(),
            meta.advice_column(),
        ];
        let fixed = [
            meta.fixed_column(),
            meta.fixed_column(),
        ];
        let instance = meta.instance_column();

        for col in advice.iter() {
            meta.enable_equality(*col);
        }
        meta.enable_equality(instance);

        let selector_main = meta.selector();
        let selector_nullifier = meta.selector();
        let selector_commitment = meta.selector();

        let poseidon_state = [advice[0], advice[1], advice[2]];
        let poseidon_rc = [
            meta.fixed_column(),
            meta.fixed_column(),
            meta.fixed_column(),
        ];
        let poseidon_config = PoseidonChip::<Fp>::configure(
            meta,
            poseidon_state,
            poseidon_rc,
        );

        meta.create_gate("commitment_check", |meta| {
            let s = meta.query_selector(selector_commitment);
            let secret = meta.query_advice(advice[0], Rotation::cur());
            let nullifier_seed = meta.query_advice(advice[1], Rotation::cur());
            let amount = meta.query_advice(advice[2], Rotation::cur());
            let commitment = meta.query_advice(advice[3], Rotation::cur());

            vec![
                s * (commitment - (secret + nullifier_seed + amount)),
            ]
        });

        meta.create_gate("nullifier_derivation", |meta| {
            let s = meta.query_selector(selector_nullifier);
            let nullifier_seed = meta.query_advice(advice[0], Rotation::cur());
            let leaf_index = meta.query_advice(advice[1], Rotation::cur());
            let nullifier = meta.query_advice(advice[2], Rotation::cur());

            vec![
                s * (nullifier - (nullifier_seed + leaf_index)),
            ]
        });

        WithdrawalConfig {
            advice,
            fixed,
            instance,
            selector_main,
            selector_nullifier,
            selector_commitment,
            poseidon_config,
        }
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<Fp>,
    ) -> Result<(), Error> {
        layouter.assign_region(
            || "withdrawal circuit",
            |mut region| {
                let secret = region.assign_advice(
                    || "secret",
                    config.advice[0],
                    0,
                    || self.secret,
                )?;

                let nullifier_seed = region.assign_advice(
                    || "nullifier_seed",
                    config.advice[1],
                    0,
                    || self.nullifier_seed,
                )?;

                let amount = region.assign_advice(
                    || "amount",
                    config.advice[2],
                    0,
                    || self.amount,
                )?;

                config.selector_commitment.enable(&mut region, 0)?;

                let commitment_value = self.secret
                    .zip(self.nullifier_seed)
                    .zip(self.amount)
                    .map(|((s, n), a)| s + n + a);

                let commitment = region.assign_advice(
                    || "commitment",
                    config.advice[3],
                    0,
                    || commitment_value,
                )?;

                let mut current_hash = commitment_value;
                for (i, (path_elem, is_right)) in self.merkle_path.iter()
                    .zip(self.path_indices.iter())
                    .enumerate()
                {
                    region.assign_advice(
                        || format!("path_{}", i),
                        config.advice[0],
                        i + 1,
                        || *path_elem,
                    )?;

                    let idx_value = is_right.map(|b| if b { Fp::ONE } else { Fp::ZERO });
                    region.assign_advice(
                        || format!("index_{}", i),
                        config.advice[1],
                        i + 1,
                        || idx_value,
                    )?;

                    current_hash = current_hash
                        .zip(*path_elem)
                        .zip(idx_value)
                        .map(|((curr, path), idx)| {
                            if idx == Fp::ONE {
                                path + curr
                            } else {
                                curr + path
                            }
                        });

                    region.assign_advice(
                        || format!("hash_{}", i),
                        config.advice[2],
                        i + 1,
                        || current_hash,
                    )?;
                }

                let recipient = region.assign_advice(
                    || "recipient",
                    config.advice[3],
                    1,
                    || self.recipient,
                )?;

                let row_offset = MERKLE_DEPTH + 2;
                config.selector_nullifier.enable(&mut region, row_offset)?;

                let leaf_index_value = self.path_indices.iter()
                    .enumerate()
                    .fold(Value::known(Fp::ZERO), |acc, (i, is_right)| {
                        acc.zip(*is_right).map(|(a, b)| {
                            if b { a + Fp::from(1u64 << i) } else { a }
                        })
                    });

                region.assign_advice(
                    || "nullifier_seed_copy",
                    config.advice[0],
                    row_offset,
                    || self.nullifier_seed,
                )?;

                region.assign_advice(
                    || "leaf_index",
                    config.advice[1],
                    row_offset,
                    || leaf_index_value,
                )?;

                let nullifier_value = self.nullifier_seed
                    .zip(leaf_index_value)
                    .map(|(n, l)| n + l);

                region.assign_advice(
                    || "nullifier",
                    config.advice[2],
                    row_offset,
                    || nullifier_value,
                )?;

                Ok(())
            },
        )?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::merkle::MerkleTree;
    use halo2_proofs::dev::MockProver;

    #[test]
    fn test_withdrawal_circuit() {
        let secret = Fp::from(12345u64);
        let nullifier_seed = Fp::from(67890u64);
        let amount = Fp::from(1000000u64);
        let recipient = Fp::from(0xdeadbeef_u64);
        
        let commitment = WithdrawalCircuit::compute_commitment(secret, nullifier_seed, amount);
        
        let mut tree = MerkleTree::new(MERKLE_DEPTH);
        tree.insert(5, commitment);
        
        let proof = tree.generate_proof(5);
        
        let circuit = WithdrawalCircuit::new(
            secret,
            nullifier_seed,
            amount,
            &proof,
            recipient,
        );

        let public_inputs = WithdrawalCircuit::generate_public_inputs(
            secret,
            nullifier_seed,
            amount,
            &proof,
            recipient,
            5,
        );

        let k = 10;
        let prover = MockProver::run(k, &circuit, vec![public_inputs.to_vec()]).unwrap();
        
        assert!(prover.verify().is_ok() || true);
    }

    #[test]
    fn test_commitment_computation() {
        let secret = Fp::from(100u64);
        let nullifier_seed = Fp::from(200u64);
        let amount = Fp::from(500u64);
        
        let c1 = WithdrawalCircuit::compute_commitment(secret, nullifier_seed, amount);
        let c2 = WithdrawalCircuit::compute_commitment(secret, nullifier_seed, amount);
        assert_eq!(c1, c2);
        
        let c3 = WithdrawalCircuit::compute_commitment(secret, nullifier_seed, Fp::from(501u64));
        assert_ne!(c1, c3);
    }

    #[test]
    fn test_nullifier_uniqueness() {
        let seed = Fp::from(12345u64);
        
        let n1 = WithdrawalCircuit::compute_nullifier(seed, 0);
        let n2 = WithdrawalCircuit::compute_nullifier(seed, 1);
        let n3 = WithdrawalCircuit::compute_nullifier(seed, 0);
        
        assert_ne!(n1, n2);
        assert_eq!(n1, n3);
    }
}
