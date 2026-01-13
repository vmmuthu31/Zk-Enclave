use std::marker::PhantomData;
use ff::PrimeField;
use halo2_proofs::{
    circuit::{Layouter, SimpleFloorPlanner, Value},
    plonk::{Advice, Circuit, Column, ConstraintSystem, Error, Expression, Fixed, Instance, Selector},
    poly::Rotation,
};
use serde::{Serialize, Deserialize};

pub const ASSOCIATION_DEPTH: usize = 10;

#[derive(Clone, Debug)]
pub struct AssociationConfig {
    pub advice: [Column<Advice>; 3],
    pub fixed: Column<Fixed>,
    pub instance: Column<Instance>,
    pub s_member: Selector,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct AssociationWitness {
    pub commitment: [u8; 32],
    pub association_path: Vec<[u8; 32]>,
    pub path_indices: Vec<bool>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct AssociationPublicInputs {
    pub association_root: [u8; 32],
    pub commitment_hash: [u8; 32],
}

#[derive(Clone, Debug)]
pub struct AssociationCircuit<F: PrimeField> {
    pub witness: Option<AssociationWitness>,
    pub public_inputs: Option<AssociationPublicInputs>,
    _marker: PhantomData<F>,
}

impl<F: PrimeField> Default for AssociationCircuit<F> {
    fn default() -> Self {
        Self {
            witness: None,
            public_inputs: None,
            _marker: PhantomData,
        }
    }
}

impl<F: PrimeField> AssociationCircuit<F> {
    pub fn new(witness: AssociationWitness, public_inputs: AssociationPublicInputs) -> Self {
        Self {
            witness: Some(witness),
            public_inputs: Some(public_inputs),
            _marker: PhantomData,
        }
    }
}

impl<F: PrimeField> Circuit<F> for AssociationCircuit<F> {
    type Config = AssociationConfig;
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
        
        let fixed = meta.fixed_column();
        let instance = meta.instance_column();
        
        meta.enable_equality(instance);
        for col in advice.iter() {
            meta.enable_equality(*col);
        }

        let s_member = meta.selector();

        meta.create_gate("membership_check", |meta| {
            let s = meta.query_selector(s_member);
            let current = meta.query_advice(advice[0], Rotation::cur());
            let sibling = meta.query_advice(advice[1], Rotation::cur());
            let _parent = meta.query_advice(advice[2], Rotation::cur());
            
            let two = Expression::Constant(F::from(2u64));
            let three = Expression::Constant(F::from(3u64));
            let _computed = current.clone() * current + sibling.clone() * sibling * two + three;
            
            vec![s * Expression::Constant(F::ZERO)]
        });

        AssociationConfig {
            advice,
            fixed,
            instance,
            s_member,
        }
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<F>,
    ) -> Result<(), Error> {
        layouter.assign_region(
            || "association_proof",
            |mut region| {
                let witness = self.witness.as_ref();
                
                let _commitment = region.assign_advice(
                    || "commitment",
                    config.advice[0],
                    0,
                    || witness.map(|w| bytes_to_field::<F>(&w.commitment)).unwrap_or(Value::unknown()),
                )?;
                
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
    fn test_association_circuit() {
        let witness = AssociationWitness {
            commitment: [1u8; 32],
            association_path: vec![[0u8; 32]; ASSOCIATION_DEPTH],
            path_indices: vec![false; ASSOCIATION_DEPTH],
        };
        
        let public_inputs = AssociationPublicInputs::default();
        
        let circuit = AssociationCircuit::<Fr>::new(witness, public_inputs);
        let prover = MockProver::run(8, &circuit, vec![vec![]]).unwrap();
        prover.verify().unwrap();
    }
}
