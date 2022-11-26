mod merkle_tree;
mod circuit;

use ark_ff::ToConstraintField;

use ark_bls12_381::Bls12_381;
use ark_groth16::Groth16;

use ark_crypto_primitives::{CircuitSpecificSetupSNARK, SNARK};

use ark_std::{rand::Rng, test_rng};

use circuit::*;
use merkle_tree::*;

fn main() {
    let rng = &mut test_rng();

    let leaves = [
        vec![1u8],
        vec![2u8],
        vec![3u8],
        vec![4u8],
        vec![5u8],
        vec![6u8],
        vec![7u8],
        vec![8u8],
    ];

    let sha256_params = ();
    let merkle_tree = Sha256MerkleTree::new(
        &sha256_params,
        &sha256_params,
        leaves.iter().map(|v| v.as_slice()),
    )
    .unwrap();

    let root = merkle_tree.root();

    let leaf_index = 0;
    let leaf = &leaves[leaf_index];
    let merkle_proof = merkle_tree.generate_proof(leaf_index).unwrap();

    // Setup params
    let (pk, vk) = {
        let dummy_leaf = vec![0u8];
        let mut dummy_leaves = Vec::new();

        for _ in 0..leaves.len() {
            dummy_leaves.push(dummy_leaf.clone());
        }

        let tree = Sha256MerkleTree::new(
            &sha256_params,
            &sha256_params,
            dummy_leaves.iter().map(|v| v.as_slice()),
        )
        .unwrap();

        let leaf_index = 1;
        let c = Sha256MerkleProofCircuit {
            root: tree.root(),
            leaf: dummy_leaves[leaf_index].clone(),
            proof: tree.generate_proof(leaf_index).unwrap(),
        };

        Groth16::<Bls12_381>::setup(c, rng).unwrap()
    };

    // Preprocess verifying key
    let pvk = Groth16::<Bls12_381>::process_vk(&vk).unwrap();

    // Build circuit
    let c = Sha256MerkleProofCircuit {
        root,
        leaf: leaf.clone(),
        proof: merkle_proof,
    };

    // Generate proof
    let proof = Groth16::<Bls12_381>::prove(&pk, c, rng).unwrap();

    // Public input
    let leaf = [1u8];
    let input = leaf.to_field_elements().ok_or("invalid leaf").unwrap();

    // Verify proof
    assert!(
        Groth16::<Bls12_381>::verify_with_processed_vk(&pvk, &input, &proof).unwrap(),
        "proof verification failed"
    );

    println!("proof verified successfully");
}
