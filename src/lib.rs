
use ark_crypto_primitives::crh::TwoToOneCRH;
use ark_crypto_primitives::merkle_tree::{Config, MerkleTree, Path};
use ark_crypto_primitives::crh::CRH;
use ark_relations::r1cs::{ConstraintLayer, ConstraintSystem, TracingMode, ConstraintSynthesizer};
use tracing_subscriber::layer::SubscriberExt;

pub mod common;
use common::*;
use crate::constraints::MTreeVerification;

mod constraints;

extern crate crypto;

use self::crypto::digest::Digest;
use self::crypto::sha3::Sha3;



#[derive(Clone)]
pub struct MerkleConfig;

impl Config for MerkleConfig {
    // Our Merkle tree relies on two hashes:
    // one to hash leaves, and one to hash pairs
    // of internal nodes.
    type LeafHash = LeafHash;
    type TwoToOneHash = TwoToOneHash;
}

/// A Merkle tree containing account information.
pub type SimpleMerkleTree = MerkleTree<MerkleConfig>;
/// The root of the account Merkle tree.
pub type Root = <TwoToOneHash as TwoToOneCRH>::Output;
/// A membership proof for a given account.
pub type SimplePath = Path<MerkleConfig>;



// Run this test via `cargo test --release test_merkle_tree`.
#[test]
fn test_merkle_tree() {

    let mut leafdata = vec![];
    for i in &[1u8, 2u8, 3u8, 10u8, 9u8, 17u8, 70u8, 45u8] {
        let mut hasher = Sha3::keccak256();
        hasher.input(&[*i]);
        leafdata.push(hasher.result_str().as_bytes().to_vec());
    }

    // Let's set up an RNG for use within tests. Note that this is *not* safe
    // for any production use.
    let mut rng = ark_std::test_rng();

    // First, let's sample the public parameters for the hash functions:
    let leaf_crh_params = <LeafHash as CRH>::setup(&mut rng).unwrap();
    let two_to_one_crh_params = <TwoToOneHash as TwoToOneCRH>::setup(&mut rng).unwrap();

    // Next, let's construct our tree.
    // This follows the API in https://github.com/arkworks-rs/crypto-primitives/blob/6be606259eab0aec010015e2cfd45e4f134cd9bf/src/merkle_tree/mod.rs#L156
    let tree = SimpleMerkleTree::new(
        &leaf_crh_params,
        &two_to_one_crh_params,
        &leafdata, // the i-th entry is the i-th leaf.
    )
        .unwrap();


    // Now, let's try to generate a membership proof for the 4th item.
    let proof = tree.generate_proof(3).unwrap(); // we're 0-indexing!

    let mut hasher = Sha3::keccak256();
    hasher.input(&[10u8]);

    let leaf = hasher.result_str().as_bytes().to_vec();
    // This should be a proof for the membership of a leaf with value 9. Let's check that!

    // First, let's get the root we want to verify against:
    let root = tree.root();
    // Next, let's verify the proof!
    let result = proof
        .verify(
            &leaf_crh_params,
            &two_to_one_crh_params,
            &root,
            &leaf, // The claimed leaf
        )
        .unwrap();
    assert!(result);
}


// Run this test via `cargo test --release test_merkle_tree`.
#[test]
fn test_merkle_tree_constraints() {

    // Let's set up an RNG for use within tests. Note that this is *not* safe
    // for any production use.
    let mut rng = ark_std::test_rng();

    // First, let's sample the public parameters for the hash functions:
    let leaf_crh_params = <LeafHash as CRH>::setup(&mut rng).unwrap();
    let two_to_one_crh_params = <TwoToOneHash as TwoToOneCRH>::setup(&mut rng).unwrap();

    let mut leafdata = vec![];
    for i in &[1u8, 2u8, 3u8, 10u8, 9u8, 17u8, 70u8, 45u8] {
        let mut hasher = Sha3::keccak256();
        hasher.input(&[*i]);
        leafdata.push(hasher.result_str().as_bytes().to_vec());
    }

    // Next, let's construct our tree.
    // This follows the API in https://github.com/arkworks-rs/crypto-primitives/blob/6be606259eab0aec010015e2cfd45e4f134cd9bf/src/merkle_tree/mod.rs#L156
    let tree = crate::SimpleMerkleTree::new(
        &leaf_crh_params,
        &two_to_one_crh_params,
        &leafdata, // the i-th entry is the i-th leaf.
    )
        .unwrap();

    let mut hasher = Sha3::keccak256();
    hasher.input(&[9u8]);

    let leaf = hasher.result_str().as_bytes().to_vec();

    // Now, let's try to generate a membership proof for the 5th item, i.e. 9.
    let proof = tree.generate_proof(4).unwrap(); // we're 0-indexing!
    // This should be a proof for the membership of a leaf with value 9. Let's check that!

    // First, let's get the root we want to verify against:
    let root = tree.root();

    let circuit = MTreeVerification {
        // constants
        leaf_crh_params,
        two_to_one_crh_params,

        // public inputs
        root,
        leaf,

        // witness
        auth_path: Some(proof),
    };
    // First, some boilerplat that helps with debugging
    let mut layer = ConstraintLayer::default();
    layer.mode = TracingMode::OnlyConstraints;
    let subscriber = tracing_subscriber::Registry::default().with(layer);
    let _guard = tracing::subscriber::set_default(subscriber);

    // Next, let's make the circuit!
    let cs = ConstraintSystem::new_ref();
    circuit.generate_constraints(cs.clone()).unwrap();
    // Let's check whether the constraint system is satisfied
    let is_satisfied = cs.is_satisfied().unwrap();
    if !is_satisfied {
        // If it isn't, find out the offending constraint.
        println!("{:?}", cs.which_is_unsatisfied());
    }
    assert!(is_satisfied);
}

