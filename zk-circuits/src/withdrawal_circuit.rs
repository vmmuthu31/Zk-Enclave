use std::marker::PhantomData;
use ff::PrimeField;
use halo2_proofs::{
    circuit::{Layouter, SimpleFloorPlanner, Value},
    plonk::{Advice, Circuit, Column, ConstraintSystem, Error, Instance, Selector},
    poly::Rotation,
};
use serde::{Serialize, Deserialize};

#[derive(Clone, Debug)]
pub struct WithdrawalConfig {
    pub advice: [Column<Advice>; 3],
    pub instance: Column<Instance>,
    pub selector: Selector,
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

#[derive(Clone, Debug)]
pub struct WithdrawalCircuit<F: PrimeField> {
    pub witness: Option<WithdrawalWitness>,
    _marker: PhantomData<F>,
}

impl<F: PrimeField> Default for WithdrawalCircuit<F> {
    fn default() -> Self {
        Self {
            witness: None,
            _marker: PhantomData,
        }
    }
}

impl<F: PrimeField> WithdrawalCircuit<F> {
    pub fn new(witness: WithdrawalWitness) -> Self {
        Self {
            witness: Some(witness),
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
        ];
        
        let instance = meta.instance_column();
        meta.enable_equality(instance);

        for col in advice.iter() {
            meta.enable_equality(*col);
        }

        let selector = meta.selector();

        meta.create_gate("dummy", |meta| {
            let s = meta.query_selector(selector);
            let a = meta.query_advice(advice[0], Rotation::cur());
            let b = meta.query_advice(advice[1], Rotation::cur());
            let c = meta.query_advice(advice[2], Rotation::cur());
            
            vec![s * (a + b - c)]
        });

        WithdrawalConfig {
            advice,
            instance,
            selector,
        }
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<F>,
    ) -> Result<(), Error> {
        layouter.assign_region(
            || "main",
            |mut region| {
                config.selector.enable(&mut region, 0)?;

                let a_val = self.witness.as_ref()
                    .map(|w| F::from(w.amount))
                    .unwrap_or(F::ZERO);
                let b_val = F::ONE;
                let c_val = a_val + b_val;

                region.assign_advice(
                    || "a",
                    config.advice[0],
                    0,
                    || Value::known(a_val),
                )?;

                region.assign_advice(
                    || "b",
                    config.advice[1],
                    0,
                    || Value::known(b_val),
                )?;

                region.assign_advice(
                    || "c",
                    config.advice[2],
                    0,
                    || Value::known(c_val),
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
    use ff::Field;
    use halo2_proofs::{
        dev::MockProver,
        halo2curves::bn256::Fr,
    };

    #[test]
    fn test_empty_circuit() {
        let circuit = WithdrawalCircuit::<Fr>::default();
        let prover = MockProver::run(4, &circuit, vec![vec![]]).unwrap();
        prover.verify().unwrap();
    }

    #[test]
    fn test_circuit_with_witness() {
        let witness = WithdrawalWitness {
            secret: [1u8; 32],
            nullifier_seed: [2u8; 32],
            amount: 1_000_000,
            leaf_index: 0,
            merkle_path: vec![[0u8; 32]; 20],
            path_indices: vec![false; 20],
        };
        
        let circuit = WithdrawalCircuit::<Fr>::new(witness);
        let prover = MockProver::run(4, &circuit, vec![vec![]]).unwrap();
        prover.verify().unwrap();
    }
}
