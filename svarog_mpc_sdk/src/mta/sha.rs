//! This file is a modified version of ING bank's NIZK-RSA implementation:
//! https://github.com/ing-bank/threshold-signatures/blob/master/src/algorithms/nizk_rsa.rs
//! to support curv-kzen from v0.2.8 to v0.9.0

//! Implements Hash trait for Sha512-256 algorithm
use curv::{
    arithmetic::{traits::Converter, BasicOps, BitManipulation},
    BigInt,
};
use rand::{thread_rng, Rng};
use sha2::{Digest, Sha512Trunc256};
use std::convert::TryFrom;

pub struct HSha512Trunc256;

impl HSha512Trunc256 {
    const MAX_ITERATIONS_IN_REJECTION_SAMPLING: usize = 256;
    pub const DIGEST_BIT_LENGTH: usize = 256;
    const NONCE_SIZE_BYTES: usize = 8;

    pub fn can_handle_curve_modulo(q: &BigInt) -> bool {
        Self::DIGEST_BIT_LENGTH == q.bit_length()
    }

    pub fn create_hash(big_ints: &[&BigInt]) -> BigInt {
        let mut hasher = Sha512Trunc256::new();

        for value in big_ints {
            let as_vec = BigInt::to_bytes(value);
            let vec_length = u16::try_from(as_vec.len()).expect("BigInt: bit length too big");
            hasher.update(vec_length.to_le_bytes());
            hasher.update(&as_vec);
        }

        let result_hex = hasher.finalize();
        BigInt::from_bytes(&result_hex[..])
    }

    pub fn create_hash_with_random_nonce(big_ints: &[&BigInt]) -> (BigInt, BigInt) {
        let mut nonce = [0u8; Self::NONCE_SIZE_BYTES];
        let mut hasher = Sha512Trunc256::new();
        thread_rng().fill(&mut nonce[..]);

        hasher.update(nonce);
        for value in big_ints {
            let as_vec = BigInt::to_bytes(value);
            let vec_length = u16::try_from(as_vec.len()).expect("BigInt: bit length too big");
            hasher.update(vec_length.to_le_bytes());
            hasher.update(&as_vec);
        }

        let result_hex = hasher.finalize();
        (
            BigInt::from_bytes(&result_hex[..]),
            BigInt::from_bytes(&nonce[0..Self::NONCE_SIZE_BYTES]),
        )
    }

    pub fn create_hash_with_nonce(big_ints: &[&BigInt], nonce: &BigInt) -> (BigInt, BigInt) {
        let mut hasher = Sha512Trunc256::new();

        let mut input = BigInt::to_bytes(nonce);
        assert!(input.len() <= Self::NONCE_SIZE_BYTES);
        while input.len() < Self::NONCE_SIZE_BYTES {
            input.insert(0, 0u8);
        }

        hasher.update(input);
        for value in big_ints {
            let as_vec = BigInt::to_bytes(value);
            let vec_length = u16::try_from(as_vec.len()).expect("BigInt: bit length too big");
            hasher.update(vec_length.to_le_bytes());
            hasher.update(&as_vec);
        }
        let result_hex = hasher.finalize();
        (BigInt::from_bytes(&result_hex[..]), nonce.clone())
    }

    pub fn create_hash_bounded_by_q(big_ints: &[&BigInt], q: &BigInt) -> (BigInt, BigInt) {
        for _ in 0..Self::MAX_ITERATIONS_IN_REJECTION_SAMPLING {
            let (hash, nonce) = Self::create_hash_with_random_nonce(big_ints);
            let hash = hash.abs();
            if hash < *q {
                return (hash, nonce);
            }
        }
        // If the condition in can_handle_curve_modulo() is true,
        // the probability of hitting next statement is no more than approx. 1/2^(MAX_ITERATIONS)
        unreachable!(
            "rejection sampling exceeded {} iterations in create_hash_bounded_by_q()",
            Self::MAX_ITERATIONS_IN_REJECTION_SAMPLING
        )
    }
}

#[cfg(test)]
mod tests {
    use super::HSha512Trunc256;
    use curv::{
        arithmetic::{traits::Samplable, BasicOps},
        elliptic::curves::{secp256_k1::Secp256k1, Scalar},
        BigInt,
    };

    #[test]
    fn hash_with_random_nonce() {
        for _ in 0..1000 {
            let alpha = BigInt::sample_below(&Scalar::<Secp256k1>::group_order().pow(3));
            let beta = BigInt::sample_below(&Scalar::<Secp256k1>::group_order().pow(3));
            let gamma = BigInt::sample_below(&alpha);
            let input_slice = [&alpha, &beta, &gamma, &alpha, &beta, &gamma];
            let (hash, nonce) = HSha512Trunc256::create_hash_with_random_nonce(&input_slice);
            let (hash_prim, nonce_prim) =
                HSha512Trunc256::create_hash_with_nonce(&input_slice, &nonce);
            assert_eq!(hash, hash_prim);
            assert_eq!(nonce, nonce_prim);
        }
    }
}
