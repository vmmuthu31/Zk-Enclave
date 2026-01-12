use halo2_proofs::{
    arithmetic::Field,
    circuit::{AssignedCell, Layouter, Region, Value},
    plonk::{Advice, Column, ConstraintSystem, Error, Expression, Selector},
    poly::Rotation,
};
use halo2curves::bn256::Fr as Fp;
use crate::poseidon::{poseidon_hash_native, PoseidonChip, PoseidonConfig};
use std::marker::PhantomData;

pub const MERKLE_DEPTH: usize = 20;

#[derive(Clone, Debug)]
pub struct MerkleTreeConfig {
    pub left: Column<Advice>,
    pub right: Column<Advice>,
    pub index: Column<Advice>,
    pub output: Column<Advice>,
    pub poseidon_config: PoseidonConfig,
    pub selector: Selector,
}

pub struct MerkleTreeChip<F: Field> {
    config: MerkleTreeConfig,
    _marker: PhantomData<F>,
}

#[derive(Clone, Debug)]
pub struct MerkleProof {
    pub path: Vec<Fp>,
    pub indices: Vec<bool>,
}

impl MerkleProof {
    pub fn new(path: Vec<Fp>, indices: Vec<bool>) -> Self {
        assert_eq!(path.len(), indices.len());
        Self { path, indices }
    }

    pub fn verify(&self, leaf: Fp, root: Fp) -> bool {
        let computed_root = self.compute_root(leaf);
        computed_root == root
    }

    pub fn compute_root(&self, leaf: Fp) -> Fp {
        let mut current = leaf;
        for (sibling, is_right) in self.path.iter().zip(self.indices.iter()) {
            let (left, right) = if *is_right {
                (*sibling, current)
            } else {
                (current, *sibling)
            };
            current = poseidon_hash_native(&[left, right]);
        }
        current
    }
}

impl<F: Field> MerkleTreeChip<F> {
    pub fn construct(config: MerkleTreeConfig) -> Self {
        Self {
            config,
            _marker: PhantomData,
        }
    }

    pub fn configure(
        meta: &mut ConstraintSystem<F>,
        left: Column<Advice>,
        right: Column<Advice>,
        index: Column<Advice>,
        output: Column<Advice>,
        poseidon_config: PoseidonConfig,
    ) -> MerkleTreeConfig {
        let selector = meta.selector();

        meta.enable_equality(left);
        meta.enable_equality(right);
        meta.enable_equality(index);
        meta.enable_equality(output);

        meta.create_gate("merkle_swap", |meta| {
            let s = meta.query_selector(selector);
            let l = meta.query_advice(left, Rotation::cur());
            let r = meta.query_advice(right, Rotation::cur());
            let idx = meta.query_advice(index, Rotation::cur());
            
            let one = Expression::Constant(F::ONE);
            let is_right = idx.clone();
            let is_left = one - idx.clone();
            
            let selected_left = is_left.clone() * l.clone() + is_right.clone() * r.clone();
            let selected_right = is_left * r + is_right * l;
            
            vec![
                s.clone() * idx.clone() * (idx.clone() - Expression::Constant(F::ONE)),
                s.clone() * (meta.query_advice(left, Rotation::next()) - selected_left),
                s * (meta.query_advice(right, Rotation::next()) - selected_right),
            ]
        });

        MerkleTreeConfig {
            left,
            right,
            index,
            output,
            poseidon_config,
            selector,
        }
    }

    pub fn verify_proof(
        &self,
        mut layouter: impl Layouter<F>,
        leaf: AssignedCell<F, F>,
        path: &[AssignedCell<F, F>],
        indices: &[AssignedCell<F, F>],
        root: AssignedCell<F, F>,
    ) -> Result<(), Error> {
        layouter.assign_region(
            || "merkle verify",
            |mut region| {
                let mut current = leaf.clone();

                for (i, (sibling, index)) in path.iter().zip(indices.iter()).enumerate() {
                    self.config.selector.enable(&mut region, i)?;

                    current.copy_advice(
                        || "current",
                        &mut region,
                        self.config.left,
                        i,
                    )?;
                    sibling.copy_advice(
                        || "sibling",
                        &mut region,
                        self.config.right,
                        i,
                    )?;
                    index.copy_advice(
                        || "index",
                        &mut region,
                        self.config.index,
                        i,
                    )?;

                    let (left_val, right_val) = current
                        .value()
                        .zip(sibling.value())
                        .zip(index.value())
                        .map(|((c, s), idx)| {
                            if *idx == F::ONE {
                                (*s, *c)
                            } else {
                                (*c, *s)
                            }
                        })
                        .unzip();

                    let hash_output = left_val.zip(right_val).map(|(l, r)| {
                        l + r
                    });

                    current = region.assign_advice(
                        || format!("hash_{}", i),
                        self.config.output,
                        i,
                        || hash_output,
                    )?;
                }

                region.constrain_equal(current.cell(), root.cell())?;

                Ok(())
            },
        )
    }
}

pub struct MerkleTree {
    leaves: Vec<Fp>,
    depth: usize,
    nodes: Vec<Vec<Fp>>,
}

impl MerkleTree {
    pub fn new(depth: usize) -> Self {
        let capacity = 1 << depth;
        let mut nodes = Vec::with_capacity(depth + 1);
        
        nodes.push(vec![Fp::ZERO; capacity]);
        
        let mut level_size = capacity;
        for _ in 0..depth {
            level_size /= 2;
            nodes.push(vec![Fp::ZERO; level_size]);
        }

        Self {
            leaves: vec![Fp::ZERO; capacity],
            depth,
            nodes,
        }
    }

    pub fn insert(&mut self, index: usize, value: Fp) {
        assert!(index < self.leaves.len());
        self.leaves[index] = value;
        self.nodes[0][index] = value;

        let mut idx = index;
        for level in 0..self.depth {
            let parent_idx = idx / 2;
            let left_idx = parent_idx * 2;
            let right_idx = left_idx + 1;

            let left = self.nodes[level][left_idx];
            let right = if right_idx < self.nodes[level].len() {
                self.nodes[level][right_idx]
            } else {
                Fp::ZERO
            };

            self.nodes[level + 1][parent_idx] = poseidon_hash_native(&[left, right]);
            idx = parent_idx;
        }
    }

    pub fn root(&self) -> Fp {
        self.nodes[self.depth][0]
    }

    pub fn generate_proof(&self, index: usize) -> MerkleProof {
        assert!(index < self.leaves.len());
        
        let mut path = Vec::with_capacity(self.depth);
        let mut indices = Vec::with_capacity(self.depth);
        
        let mut idx = index;
        for level in 0..self.depth {
            let is_right = idx % 2 == 1;
            let sibling_idx = if is_right { idx - 1 } else { idx + 1 };
            
            let sibling = if sibling_idx < self.nodes[level].len() {
                self.nodes[level][sibling_idx]
            } else {
                Fp::ZERO
            };
            
            path.push(sibling);
            indices.push(is_right);
            idx /= 2;
        }

        MerkleProof { path, indices }
    }

    pub fn verify_proof(&self, leaf: Fp, proof: &MerkleProof) -> bool {
        proof.verify(leaf, self.root())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_merkle_tree_basic() {
        let mut tree = MerkleTree::new(4);
        
        let leaf0 = poseidon_hash_native(&[Fp::from(100u64), Fp::from(1u64)]);
        let leaf1 = poseidon_hash_native(&[Fp::from(200u64), Fp::from(2u64)]);
        
        tree.insert(0, leaf0);
        tree.insert(1, leaf1);
        
        let root = tree.root();
        assert_ne!(root, Fp::ZERO);
        
        let proof0 = tree.generate_proof(0);
        assert!(proof0.verify(leaf0, root));
        
        let proof1 = tree.generate_proof(1);
        assert!(proof1.verify(leaf1, root));
        
        assert!(!proof0.verify(leaf1, root));
    }

    #[test]
    fn test_merkle_proof_at_depth() {
        let mut tree = MerkleTree::new(MERKLE_DEPTH);
        
        let leaf = poseidon_hash_native(&[Fp::from(12345u64), Fp::from(67890u64)]);
        tree.insert(1000, leaf);
        
        let proof = tree.generate_proof(1000);
        assert_eq!(proof.path.len(), MERKLE_DEPTH);
        
        assert!(proof.verify(leaf, tree.root()));
    }
}
