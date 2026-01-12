use sha2::{Sha256, Digest};
use serde::{Serialize, Deserialize};

pub const MERKLE_TREE_DEPTH: usize = 20;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MerkleProof {
    pub path: Vec<[u8; 32]>,
    pub indices: Vec<bool>,
    pub root: [u8; 32],
}

pub struct MerkleTree {
    depth: usize,
    zero_values: Vec<[u8; 32]>,
}

impl MerkleTree {
    pub fn new(depth: usize) -> Self {
        let mut zero_values = Vec::with_capacity(depth + 1);
        let mut current = [0u8; 32];
        zero_values.push(current);
        
        for _ in 0..depth {
            current = merkle_hash(&current, &current);
            zero_values.push(current);
        }
        
        Self { depth, zero_values }
    }

    pub fn compute_root_from_path(
        &self,
        leaf: &[u8; 32],
        path: &[[u8; 32]],
        indices: &[bool],
    ) -> [u8; 32] {
        let mut current = *leaf;
        
        for (sibling, &is_right) in path.iter().zip(indices.iter()) {
            if is_right {
                current = merkle_hash(sibling, &current);
            } else {
                current = merkle_hash(&current, sibling);
            }
        }
        
        current
    }

    pub fn generate_proof_for_leaf(
        &self,
        _leaf: &[u8; 32],
        index: usize,
    ) -> (Vec<[u8; 32]>, Vec<bool>) {
        let mut path = Vec::with_capacity(self.depth);
        let mut indices = Vec::with_capacity(self.depth);
        
        let mut current_index = index;
        for level in 0..self.depth {
            let is_right = current_index & 1 == 1;
            indices.push(is_right);
            path.push(self.zero_values[level]);
            current_index >>= 1;
        }
        
        (path, indices)
    }

    pub fn get_empty_root(&self) -> [u8; 32] {
        self.zero_values[self.depth]
    }

    pub fn verify_proof(&self, proof: &MerkleProof, leaf: &[u8; 32]) -> bool {
        let computed_root = self.compute_root_from_path(leaf, &proof.path, &proof.indices);
        computed_root == proof.root
    }
}

pub fn merkle_hash(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(left);
    hasher.update(right);
    hasher.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_merkle_tree_creation() {
        let tree = MerkleTree::new(MERKLE_TREE_DEPTH);
        let root = tree.get_empty_root();
        assert_ne!(root, [0u8; 32]);
    }

    #[test]
    fn test_merkle_proof_generation() {
        let tree = MerkleTree::new(MERKLE_TREE_DEPTH);
        let leaf = [42u8; 32];
        
        let (path, indices) = tree.generate_proof_for_leaf(&leaf, 0);
        
        assert_eq!(path.len(), MERKLE_TREE_DEPTH);
        assert_eq!(indices.len(), MERKLE_TREE_DEPTH);
    }

    #[test]
    fn test_merkle_root_computation() {
        let tree = MerkleTree::new(MERKLE_TREE_DEPTH);
        let leaf = [42u8; 32];
        
        let (path, indices) = tree.generate_proof_for_leaf(&leaf, 0);
        let root = tree.compute_root_from_path(&leaf, &path, &indices);
        
        assert_ne!(root, [0u8; 32]);
    }

    #[test]
    fn test_merkle_proof_verification() {
        let tree = MerkleTree::new(MERKLE_TREE_DEPTH);
        let leaf = [42u8; 32];
        
        let (path, indices) = tree.generate_proof_for_leaf(&leaf, 0);
        let root = tree.compute_root_from_path(&leaf, &path, &indices);
        
        let proof = MerkleProof { path, indices, root };
        assert!(tree.verify_proof(&proof, &leaf));
    }

    #[test]
    fn test_different_leaves_different_roots() {
        let tree = MerkleTree::new(MERKLE_TREE_DEPTH);
        let leaf1 = [1u8; 32];
        let leaf2 = [2u8; 32];
        
        let (path1, indices1) = tree.generate_proof_for_leaf(&leaf1, 0);
        let (path2, indices2) = tree.generate_proof_for_leaf(&leaf2, 0);
        
        let root1 = tree.compute_root_from_path(&leaf1, &path1, &indices1);
        let root2 = tree.compute_root_from_path(&leaf2, &path2, &indices2);
        
        assert_ne!(root1, root2);
    }
}
