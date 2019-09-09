use blake2b_rs::Blake2bBuilder;
pub const BLAKE2B_KEY: &[u8] = &[];
pub const BLAKE2B_LEN: usize = 32;
pub const PERSONALIZATION: &[u8] = b"sparsemerkletree";

use std::borrow::Cow;
const TREE_HEIGHT: usize = std::mem::size_of::<H256>() * 8;


use std::collections::HashMap;

pub type H256 = [u8; 32];
type TreeCache = HashMap<H256, (H256, H256)>;

//const TREE_HEIGHT: usize = std::mem::size_of::<H256>() * 8;
const HIGHEST_BIT_POS: u8 = 7;

#[derive(Debug, Clone, PartialEq)]
pub enum Error {
    MissingKey(H256),
}

pub type Result<T> = ::std::result::Result<T, Error>;

enum Branch {
    Left = 0,
    Right = 1,
}

struct PathIter<'a> {
    path: &'a H256,
    bit_pos: u8,
    byte_pos: u8,
}

fn merge(lhs: &H256, rhs: &H256) -> H256 {
    let mut hash = [0u8; 32];
    let mut hasher = Blake2bBuilder::new(BLAKE2B_LEN)
        .personal(PERSONALIZATION)
        .key(BLAKE2B_KEY)
        .build();

    hasher.update(lhs);
    hasher.update(rhs);
    hasher.finalize(&mut hash);
    hash
}

impl<'a> From<&'a H256> for PathIter<'a> {
    fn from(path: &'a H256) -> Self {
        PathIter {
            path,
            bit_pos: 0,
            byte_pos: 0,
        }
    }
}

impl<'a> Iterator for PathIter<'a> {
    type Item = Branch;
    fn next(&mut self) -> Option<Self::Item> {
        if let Some(byte) = self.path.get(self.byte_pos as usize) {
            let branch = if (byte >> (HIGHEST_BIT_POS - self.bit_pos)) & 1 == 1 {
                Branch::Right
            } else {
                Branch::Left
            };
            if self.bit_pos == HIGHEST_BIT_POS {
                self.byte_pos += 1;
                self.bit_pos = 0;
            } else {
                self.bit_pos += 1;
            }
            Some(branch)
        } else {
            None
        }
    }
}

pub struct SparseMerkleTree {
    pub cache: TreeCache,
    pub root: H256,
}

impl Default for SparseMerkleTree {
    fn default() -> Self {
        let mut hash = [0u8; 32]; // zero_hash
        let mut cache: TreeCache = Default::default();
        for _ in 0..256 {
            let parent = merge(&hash, &hash);
            cache.insert(parent, (hash, hash));
            hash = parent;
        }
        SparseMerkleTree::new(hash, cache.clone())
    }
}

impl SparseMerkleTree {
    /// create a merkle tree from root and cache
    pub fn new(root: H256, cache: TreeCache) -> SparseMerkleTree {
        SparseMerkleTree { root, cache }
    }

    /// update a leaf value, return new root
    pub fn update(&mut self, key: &H256, value: H256) -> Result<&H256> {
        let mut node = &self.root;
        let mut siblings = Vec::with_capacity(256);
        for branch in PathIter::from(key) {
            let parent = &self.cache.get(node).ok_or(Error::MissingKey(*node))?;
            match branch {
                Branch::Left => {
                    siblings.push(parent.1);
                    node = &parent.0;
                }
                Branch::Right => {
                    siblings.push(parent.0);
                    node = &parent.1;
                }
            }
        }
        let mut node = value;
        for branch in PathIter::from(key).collect::<Vec<_>>().into_iter().rev() {
            let sibling = siblings.pop().expect("sibling should exsits");
            match branch {
                Branch::Left => {
                    let new_parent = merge(&node, &sibling);
                    self.cache.insert(new_parent, (node, sibling));
                    node = new_parent;
                }
                Branch::Right => {
                    let new_parent = merge(&sibling, &node);
                    self.cache.insert(new_parent, (sibling, node));
                    node = new_parent;
                }
            }
        }
        self.root = node;
        Ok(&self.root)
    }

    /// get value of a leaf
    pub fn get(&self, key: &H256) -> Result<&H256> {
        let mut node = &self.root;
        for branch in PathIter::from(key) {
            let children = self.cache.get(node).ok_or(Error::MissingKey(*node))?;
            match branch {
                Branch::Left => node = &children.0,
                Branch::Right => node = &children.1,
            }
        }
        Ok(node)
    }
    /// generate merkle proof
    pub fn merkle_proof(&self, key: &H256) -> Result<Vec<H256>> {
        let mut node = &self.root;
        let mut proof = Vec::with_capacity(256);
        for branch in PathIter::from(key) {
            let parent = &self.cache.get(node).ok_or(Error::MissingKey(*node))?;
            match branch {
                Branch::Left => {
                    proof.push(parent.1);
                    node = &parent.0;
                }
                Branch::Right => {
                    proof.push(parent.0);
                    node = &parent.1;
                }
            }
        }
        Ok(proof)
    }
}

pub fn verify_proof(proof: &[H256], root: &H256, key: &H256, value: &H256) -> bool {
    if proof.len() != TREE_HEIGHT {
        return false;
    }
    let mut node = Cow::Borrowed(value);
    for (i, branch) in PathIter::from(key)
        .collect::<Vec<_>>()
        .into_iter()
        .rev()
        .enumerate()
    {
        let sibling = match proof.get(TREE_HEIGHT - i - 1) {
            Some(sibling) => sibling,
            None => {
                return false;
            }
        };
        match branch {
            Branch::Left => {
                node = Cow::Owned(merge(node.as_ref(), sibling));
            }
            Branch::Right => {
                node = Cow::Owned(merge(sibling, node.as_ref()));
            }
        }
    }
    root == node.as_ref()
}

fn main() {
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_default_root() {
        let tree = SparseMerkleTree::default();
        assert_eq!(tree.cache.len(), 256);
        assert_eq!(
            tree.root,
            [
                196, 132, 51, 8, 180, 167, 239, 184, 118, 169, 184, 200, 14, 177, 93, 124, 168,
                217, 185, 198, 139, 96, 205, 180, 89, 151, 241, 223, 31, 135, 83, 182
            ]
        );
    }

    use rand::{thread_rng, Rng};

    fn random_h256(rng: &mut impl Rng) -> H256 {
        let mut buf = [0u8; 32];
        rng.fill(&mut buf);
        buf
    }

    fn random_smt(update_count: usize, rng: &mut impl Rng) -> SparseMerkleTree {
        let mut smt = SparseMerkleTree::default();
        for _ in 0..update_count {
            let key = random_h256(rng);
            let value = random_h256(rng);
            smt.update(&key, value).unwrap();
        }
        smt
    }

    #[test]
    fn test_merkle_proof() {
        let mut rng = thread_rng();
        let smt = random_smt(10_000, &mut rng);
        let key = random_h256(&mut rng);
        let value = smt.get(&key).unwrap();
        let mut tree = SparseMerkleTree::default();

        tree.update(&key, *value).expect("update");
        let proof = tree.merkle_proof(&key).expect("proof");
        assert!(verify_proof(&proof, &tree.root, &key, &value));
    }
}