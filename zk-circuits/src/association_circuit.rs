use halo2_proofs::{
    arithmetic::Field,
    circuit::{Layouter, SimpleFloorPlanner, Value},
    plonk::{Advice, Circuit, Column, ConstraintSystem, Error, Fixed, Instance, Selector},
    poly::Rotation,
};
use halo2curves::bn256::Fr as Fp;
use crate::poseidon::{poseidon_hash_native, PoseidonChip, PoseidonConfig};
use crate::merkle::{MerkleProof, MERKLE_DEPTH};

#[derive(Clone, Debug)]
pub struct AssociationPublicInputs {
    pub deposit_root: Fp,
    pub association_root: Fp,
}

impl AssociationPublicInputs {
    pub fn to_vec(&self) -> Vec<Fp> {
        vec![self.deposit_root, self.association_root]
    }

    pub fn from_slice(slice: &[Fp]) -> Self {
        assert!(slice.len() >= 2);
        Self {
            deposit_root: slice[0],
            association_root: slice[1],
        }
    }
}

#[derive(Clone)]
pub struct AssociationConfig {
    pub advice: [Column<Advice>; 4],
    pub fixed: [Column<Fixed>; 2],
    pub instance: Column<Instance>,
    pub selector_merkle: Selector,
    pub selector_association: Selector,
    pub poseidon_config: PoseidonConfig,
}

#[derive(Clone, Default)]
pub struct AssociationCircuit {
    pub deposit_commitment: Value<Fp>,
    pub deposit_path: Vec<Value<Fp>>,
    pub deposit_indices: Vec<Value<bool>>,
    pub association_path: Vec<Value<Fp>>,
    pub association_indices: Vec<Value<bool>>,
}

impl AssociationCircuit {
    pub fn new(
        deposit_commitment: Fp,
        deposit_proof: &MerkleProof,
        association_proof: &MerkleProof,
    ) -> Self {
        Self {
            deposit_commitment: Value::known(deposit_commitment),
            deposit_path: deposit_proof.path.iter().map(|&p| Value::known(p)).collect(),
            deposit_indices: deposit_proof.indices.iter().map(|&i| Value::known(i)).collect(),
            association_path: association_proof.path.iter().map(|&p| Value::known(p)).collect(),
            association_indices: association_proof.indices.iter().map(|&i| Value::known(i)).collect(),
        }
    }

    pub fn generate_public_inputs(
        deposit_commitment: Fp,
        deposit_proof: &MerkleProof,
        association_proof: &MerkleProof,
    ) -> AssociationPublicInputs {
        let deposit_root = deposit_proof.compute_root(deposit_commitment);
        let association_root = association_proof.compute_root(deposit_commitment);

        AssociationPublicInputs {
            deposit_root,
            association_root,
        }
    }
}

impl Circuit<Fp> for AssociationCircuit {
    type Config = AssociationConfig;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self {
            deposit_commitment: Value::unknown(),
            deposit_path: vec![Value::unknown(); MERKLE_DEPTH],
            deposit_indices: vec![Value::unknown(); MERKLE_DEPTH],
            association_path: vec![Value::unknown(); MERKLE_DEPTH],
            association_indices: vec![Value::unknown(); MERKLE_DEPTH],
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

        let selector_merkle = meta.selector();
        let selector_association = meta.selector();

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

        meta.create_gate("merkle_path_hash", |meta| {
            let s = meta.query_selector(selector_merkle);
            let current = meta.query_advice(advice[0], Rotation::cur());
            let sibling = meta.query_advice(advice[1], Rotation::cur());
            let index = meta.query_advice(advice[2], Rotation::cur());
            let next = meta.query_advice(advice[0], Rotation::next());

            let one = halo2_proofs::plonk::Expression::Constant(Fp::ONE);
            let is_right = index.clone();
            let is_left = one - index.clone();

            let hash_input = is_left.clone() * current.clone() + is_right.clone() * sibling.clone()
                + is_left * sibling + is_right * current;

            vec![
                s.clone() * index.clone() * (index.clone() - halo2_proofs::plonk::Expression::Constant(Fp::ONE)),
                s * (next - hash_input),
            ]
        });

        AssociationConfig {
            advice,
            fixed,
            instance,
            selector_merkle,
            selector_association,
            poseidon_config,
        }
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<Fp>,
    ) -> Result<(), Error> {
        layouter.assign_region(
            || "association circuit",
            |mut region| {
                let commitment = region.assign_advice(
                    || "commitment",
                    config.advice[0],
                    0,
                    || self.deposit_commitment,
                )?;

                let mut current = self.deposit_commitment;
                for (i, (path_elem, is_right)) in self.deposit_path.iter()
                    .zip(self.deposit_indices.iter())
                    .enumerate()
                {
                    config.selector_merkle.enable(&mut region, i)?;

                    region.assign_advice(
                        || format!("deposit_current_{}", i),
                        config.advice[0],
                        i,
                        || current,
                    )?;

                    region.assign_advice(
                        || format!("deposit_sibling_{}", i),
                        config.advice[1],
                        i,
                        || *path_elem,
                    )?;

                    let idx_value = is_right.map(|b| if b { Fp::ONE } else { Fp::ZERO });
                    region.assign_advice(
                        || format!("deposit_index_{}", i),
                        config.advice[2],
                        i,
                        || idx_value,
                    )?;

                    current = current
                        .zip(*path_elem)
                        .zip(idx_value)
                        .map(|((curr, path), idx)| {
                            if idx == Fp::ONE {
                                path + curr
                            } else {
                                curr + path
                            }
                        });
                }

                let deposit_root = region.assign_advice(
                    || "deposit_root",
                    config.advice[0],
                    MERKLE_DEPTH,
                    || current,
                )?;

                let offset = MERKLE_DEPTH + 1;
                current = self.deposit_commitment;

                for (i, (path_elem, is_right)) in self.association_path.iter()
                    .zip(self.association_indices.iter())
                    .enumerate()
                {
                    let row = offset + i;
                    config.selector_association.enable(&mut region, row)?;

                    region.assign_advice(
                        || format!("assoc_current_{}", i),
                        config.advice[0],
                        row,
                        || current,
                    )?;

                    region.assign_advice(
                        || format!("assoc_sibling_{}", i),
                        config.advice[1],
                        row,
                        || *path_elem,
                    )?;

                    let idx_value = is_right.map(|b| if b { Fp::ONE } else { Fp::ZERO });
                    region.assign_advice(
                        || format!("assoc_index_{}", i),
                        config.advice[2],
                        row,
                        || idx_value,
                    )?;

                    current = current
                        .zip(*path_elem)
                        .zip(idx_value)
                        .map(|((curr, path), idx)| {
                            if idx == Fp::ONE {
                                path + curr
                            } else {
                                curr + path
                            }
                        });
                }

                let association_root = region.assign_advice(
                    || "association_root",
                    config.advice[0],
                    offset + MERKLE_DEPTH,
                    || current,
                )?;

                Ok(())
            },
        )?;

        Ok(())
    }
}

pub struct AssociationSetProvider {
    commitments: Vec<Fp>,
    tree: crate::merkle::MerkleTree,
}

impl AssociationSetProvider {
    pub fn new() -> Self {
        Self {
            commitments: Vec::new(),
            tree: crate::merkle::MerkleTree::new(MERKLE_DEPTH),
        }
    }

    pub fn add_commitment(&mut self, commitment: Fp) -> usize {
        let index = self.commitments.len();
        self.commitments.push(commitment);
        self.tree.insert(index, commitment);
        index
    }

    pub fn contains(&self, commitment: Fp) -> bool {
        self.commitments.contains(&commitment)
    }

    pub fn root(&self) -> Fp {
        self.tree.root()
    }

    pub fn generate_proof(&self, commitment: Fp) -> Option<MerkleProof> {
        self.commitments
            .iter()
            .position(|&c| c == commitment)
            .map(|index| self.tree.generate_proof(index))
    }

    pub fn size(&self) -> usize {
        self.commitments.len()
    }
}

impl Default for AssociationSetProvider {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::merkle::MerkleTree;
    use halo2_proofs::dev::MockProver;

    #[test]
    fn test_association_set_provider() {
        let mut asp = AssociationSetProvider::new();
        
        let c1 = Fp::from(12345u64);
        let c2 = Fp::from(67890u64);
        
        asp.add_commitment(c1);
        asp.add_commitment(c2);
        
        assert!(asp.contains(c1));
        assert!(asp.contains(c2));
        assert!(!asp.contains(Fp::from(99999u64)));
        
        let proof = asp.generate_proof(c1);
        assert!(proof.is_some());
        
        let proof = proof.unwrap();
        assert!(proof.verify(c1, asp.root()));
    }

    #[test]
    fn test_association_circuit_structure() {
        let commitment = Fp::from(12345u64);
        
        let mut deposit_tree = MerkleTree::new(MERKLE_DEPTH);
        deposit_tree.insert(0, commitment);
        let deposit_proof = deposit_tree.generate_proof(0);
        
        let mut asp = AssociationSetProvider::new();
        asp.add_commitment(commitment);
        let association_proof = asp.generate_proof(commitment).unwrap();
        
        let circuit = AssociationCircuit::new(
            commitment,
            &deposit_proof,
            &association_proof,
        );
        
        let public_inputs = AssociationCircuit::generate_public_inputs(
            commitment,
            &deposit_proof,
            &association_proof,
        );
        
        assert_eq!(public_inputs.deposit_root, deposit_tree.root());
        assert_eq!(public_inputs.association_root, asp.root());
    }
}
