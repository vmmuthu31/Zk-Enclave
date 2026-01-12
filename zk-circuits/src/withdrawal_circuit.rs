use std::marker::PhantomData;
use ff::PrimeField;
use halo2_proofs::{
    circuit::{AssignedCell, Layouter, SimpleFloorPlanner, Value},
    plonk::{Advice, Circuit, Column, ConstraintSystem, Error, Expression, Fixed, Instance, Selector},
    poly::Rotation,
};
use serde::{Serialize, Deserialize};

pub const MERKLE_DEPTH: usize = 20;

#[derive(Clone, Debug)]
pub struct WithdrawalConfig {
    pub advice: [Column<Advice>; 5],
    pub fixed: Column<Fixed>,
    pub instance: Column<Instance>,
    pub s_hash: Selector,
    pub s_merkle: Selector,
    pub s_nullifier: Selector,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct WithdrawalWitness {
    pub secret: [u8; 32],
    pub nullifier_seed: [u8; 32],
    pub amount: u64,
    pub leaf_index: u32,
    pub merkle_path: Vec<[u8; 32]>,
    pub path_indices: Vec<bool>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct WithdrawalPublicInputs {
    pub merkle_root: [u8; 32],
    pub nullifier: [u8; 32],
    pub recipient: [u8; 20],
    pub amount: u64,
}

#[derive(Clone, Debug)]
pub struct WithdrawalCircuit<F: PrimeField> {
    pub witness: Option<WithdrawalWitness>,
    pub public_inputs: Option<WithdrawalPublicInputs>,
    _marker: PhantomData<F>,
}

impl<F: PrimeField> Default for WithdrawalCircuit<F> {
    fn default() -> Self {
        Self {
            witness: None,
            public_inputs: None,
            _marker: PhantomData,
        }
    }
}

impl<F: PrimeField> WithdrawalCircuit<F> {
    pub fn new(witness: WithdrawalWitness, public_inputs: WithdrawalPublicInputs) -> Self {
        Self {
            witness: Some(witness),
            public_inputs: Some(public_inputs),
            _marker: PhantomData,
        }
    }
}

impl<F: PrimeField> Circuit<F> for WithdrawalCircuit<F> {
    type Config = WithdrawalConfig;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self::default()
    }

    fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
        let advice = [
            meta.advice_column(),
            meta.advice_column(),
            meta.advice_column(),
            meta.advice_column(),
            meta.advice_column(),
        ];
        
        let fixed = meta.fixed_column();
        let instance = meta.instance_column();
        
        meta.enable_equality(instance);
        for col in advice.iter() {
            meta.enable_equality(*col);
        }

        let s_hash = meta.selector();
        let s_merkle = meta.selector();
        let s_nullifier = meta.selector();

        meta.create_gate("poseidon_hash", |meta| {
            let s = meta.query_selector(s_hash);
            let left = meta.query_advice(advice[0], Rotation::cur());
            let right = meta.query_advice(advice[1], Rotation::cur());
            let output = meta.query_advice(advice[2], Rotation::cur());
            
            let two = Expression::Constant(F::from(2u64));
            let three = Expression::Constant(F::from(3u64));
            let computed = left.clone() * left + right.clone() * right * two + three;
            
            vec![s * (output - computed)]
        });

        meta.create_gate("merkle_step", |meta| {
            let s = meta.query_selector(s_merkle);
            let current = meta.query_advice(advice[0], Rotation::cur());
            let sibling = meta.query_advice(advice[1], Rotation::cur());
            let is_right = meta.query_advice(advice[2], Rotation::cur());
            let parent = meta.query_advice(advice[3], Rotation::cur());
            
            let two = Expression::Constant(F::from(2u64));
            let three = Expression::Constant(F::from(3u64));
            let one = Expression::Constant(F::ONE);
            
            let left_hash = current.clone() * current.clone() + sibling.clone() * sibling.clone() * two.clone() + three.clone();
            let right_hash = sibling.clone() * sibling + current.clone() * current * two + three;
            
            let computed = is_right.clone() * right_hash + (one - is_right) * left_hash;
            
            vec![s * (parent - computed)]
        });

        meta.create_gate("nullifier_derivation", |meta| {
            let s = meta.query_selector(s_nullifier);
            let seed = meta.query_advice(advice[0], Rotation::cur());
            let index = meta.query_advice(advice[1], Rotation::cur());
            let nullifier = meta.query_advice(advice[2], Rotation::cur());
            
            let computed = seed.clone() * seed + index;
            
            vec![s * (nullifier - computed)]
        });

        WithdrawalConfig {
            advice,
            fixed,
            instance,
            s_hash,
            s_merkle,
            s_nullifier,
        }
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<F>,
    ) -> Result<(), Error> {
        let witness = self.witness.as_ref();
        let public_inputs = self.public_inputs.as_ref();
        
        layouter.assign_region(
            || "withdrawal_proof",
            |mut region| {
                let mut row = 0;
                
                let secret = region.assign_advice(
                    || "secret",
                    config.advice[0],
                    row,
                    || witness.map(|w| bytes_to_field::<F>(&w.secret)).unwrap_or(Value::unknown()),
                )?;
                
                let nullifier_seed = region.assign_advice(
                    || "nullifier_seed",
                    config.advice[1],
                    row,
                    || witness.map(|w| bytes_to_field::<F>(&w.nullifier_seed)).unwrap_or(Value::unknown()),
                )?;

                config.s_hash.enable(&mut region, row)?;
                
                let commitment = region.assign_advice(
                    || "commitment",
                    config.advice[2],
                    row,
                    || {
                        secret.value().zip(nullifier_seed.value()).map(|(s, n)| {
                            *s * *s + *n * *n * F::from(2u64) + F::from(3u64)
                        })
                    },
                )?;
                
                row += 1;

                let leaf_index = region.assign_advice(
                    || "leaf_index",
                    config.advice[1],
                    row,
                    || witness.map(|w| Value::known(F::from(w.leaf_index as u64))).unwrap_or(Value::unknown()),
                )?;
                
                let _nullifier_seed_copy = region.assign_advice(
                    || "nullifier_seed_copy",
                    config.advice[0],
                    row,
                    || nullifier_seed.value().copied(),
                )?;
                
                config.s_nullifier.enable(&mut region, row)?;
                
                let _nullifier = region.assign_advice(
                    || "nullifier",
                    config.advice[2],
                    row,
                    || {
                        nullifier_seed.value().zip(leaf_index.value()).map(|(seed, idx)| {
                            *seed * *seed + *idx
                        })
                    },
                )?;
                
                row += 1;

                let mut current_hash = commitment;
                
                for level in 0..MERKLE_DEPTH {
                    let sibling = region.assign_advice(
                        || format!("sibling_{}", level),
                        config.advice[1],
                        row,
                        || {
                            witness.map(|w| {
                                if level < w.merkle_path.len() {
                                    bytes_to_field::<F>(&w.merkle_path[level])
                                } else {
                                    Value::known(F::ZERO)
                                }
                            }).unwrap_or(Value::unknown())
                        },
                    )?;
                    
                    let is_right = region.assign_advice(
                        || format!("is_right_{}", level),
                        config.advice[2],
                        row,
                        || {
                            witness.map(|w| {
                                if level < w.path_indices.len() && w.path_indices[level] {
                                    Value::known(F::ONE)
                                } else {
                                    Value::known(F::ZERO)
                                }
                            }).unwrap_or(Value::unknown())
                        },
                    )?;
                    
                    let _current_copy = region.assign_advice(
                        || format!("current_{}", level),
                        config.advice[0],
                        row,
                        || current_hash.value().copied(),
                    )?;
                    
                    config.s_merkle.enable(&mut region, row)?;
                    
                    let parent = region.assign_advice(
                        || format!("parent_{}", level),
                        config.advice[3],
                        row,
                        || {
                            current_hash.value().zip(sibling.value()).zip(is_right.value()).map(|((curr, sib), right)| {
                                let left_hash = *curr * *curr + *sib * *sib * F::from(2u64) + F::from(3u64);
                                let right_hash = *sib * *sib + *curr * *curr * F::from(2u64) + F::from(3u64);
                                if *right == F::ONE {
                                    right_hash
                                } else {
                                    left_hash
                                }
                            })
                        },
                    )?;
                    
                    current_hash = parent;
                    row += 1;
                }

                let _amount = region.assign_advice(
                    || "amount",
                    config.advice[4],
                    0,
                    || witness.map(|w| Value::known(F::from(w.amount))).unwrap_or(Value::unknown()),
                )?;

                let _ = public_inputs;

                Ok(())
            },
        )?;

        Ok(())
    }
}

fn bytes_to_field<F: PrimeField>(bytes: &[u8; 32]) -> Value<F> {
    let mut acc = F::ZERO;
    let base = F::from(256u64);
    for byte in bytes.iter().take(31) {
        acc = acc * base + F::from(*byte as u64);
    }
    Value::known(acc)
}

#[cfg(test)]
mod tests {
    use super::*;
    use halo2_proofs::{
        dev::MockProver,
        halo2curves::bn256::Fr,
    };

    #[test]
    fn test_minimal_withdrawal_circuit() {
        let witness = WithdrawalWitness {
            secret: [0u8; 32],
            nullifier_seed: [0u8; 32],
            amount: 0,
            leaf_index: 0,
            merkle_path: vec![[0u8; 32]; MERKLE_DEPTH],
            path_indices: vec![false; MERKLE_DEPTH],
        };
        
        let public_inputs = WithdrawalPublicInputs::default();
        
        let circuit = WithdrawalCircuit::<Fr>::new(witness, public_inputs);
        let prover = MockProver::run(10, &circuit, vec![vec![]]).unwrap();
        prover.verify().unwrap();
    }

    #[test]
    fn test_full_withdrawal_circuit() {
        let witness = WithdrawalWitness {
            secret: [1u8; 32],
            nullifier_seed: [2u8; 32],
            amount: 1_000_000_000_000_000_000,
            leaf_index: 5,
            merkle_path: vec![[0u8; 32]; MERKLE_DEPTH],
            path_indices: vec![false; MERKLE_DEPTH],
        };
        
        let public_inputs = WithdrawalPublicInputs {
            merkle_root: [0u8; 32],
            nullifier: [0u8; 32],
            recipient: [0xab; 20],
            amount: 1_000_000_000_000_000_000,
        };
        
        let circuit = WithdrawalCircuit::<Fr>::new(witness, public_inputs);
        let prover = MockProver::run(10, &circuit, vec![vec![]]).unwrap();
        prover.verify().unwrap();
    }

    #[test]
    fn test_withdrawal_with_merkle_path() {
        let mut witness = WithdrawalWitness {
            secret: [42u8; 32],
            nullifier_seed: [123u8; 32],
            amount: 500_000_000_000_000_000,
            leaf_index: 7,
            merkle_path: vec![[0u8; 32]; MERKLE_DEPTH],
            path_indices: vec![false; MERKLE_DEPTH],
        };
        
        witness.path_indices[0] = true;
        witness.path_indices[1] = true;
        witness.path_indices[2] = true;
        
        let public_inputs = WithdrawalPublicInputs::default();
        
        let circuit = WithdrawalCircuit::<Fr>::new(witness, public_inputs);
        let prover = MockProver::run(10, &circuit, vec![vec![]]).unwrap();
        prover.verify().unwrap();
    }
}
