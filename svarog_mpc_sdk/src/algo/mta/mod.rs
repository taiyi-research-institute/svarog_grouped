//! This file is a modified version of Kzen Networks' range proofs implementation:
//! https://github.com/ZenGo-X/multi-party-ecdsa/blob/master/src/utilities/mta/mod.rs
//! and borrows some definitions from ING bank's range proofs implementation:
//! https://github.com/ing-bank/threshold-signatures/blob/master/src/algorithms/zkp.rs

/*
    Multi-party ECDSA

    Copyright 2018 by Kzen Networks

    This file is part of Multi-party ECDSA library
    (https://github.com/KZen-networks/multi-party-ecdsa)

    Multi-party ECDSA is free software: you can redistribute
    it and/or modify it under the terms of the GNU General Public
    License as published by the Free Software Foundation, either
    version 3 of the License, or (at your option) any later version.

    @license GPL-3.0+ <https://github.com/KZen-networks/multi-party-ecdsa/blob/master/LICENSE>
*/

mod primes;
pub use primes::*;
mod nizk_rsa;
pub use nizk_rsa::*;
mod sha;
pub use sha::*;
mod sampling;
pub use sampling::*;
pub mod dlog_proof;
pub mod range_proofs;

///current recommended bit size for the primes in Paillier schema
pub(crate) const PRIME_BIT_LENGTH_IN_PAILLIER_SCHEMA: usize = 1024;

/// MtA is described in https://eprint.iacr.org/2019/114.pdf section 3
use curv::{
    arithmetic::traits::Samplable,
    cryptographic_primitives::proofs::sigma_dlog::DLogProof,
    elliptic::curves::{secp256_k1::Secp256k1, Point, Scalar},
    BigInt,
};
use paillier::{
    traits::EncryptWithChosenRandomness, Add, Decrypt, DecryptionKey, EncryptionKey, Mul, Paillier,
    Randomness, RawCiphertext, RawPlaintext,
};
use xuanmi_base_support::*;
use zk_paillier::zkproofs::DLogStatement;

use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::borrow::Borrow;

use crate::algo::mta::{
    range_proofs::{AliceProof, BobProof, BobProofExt},
    BobProofType::{RangeProof, RangeProofExt},
};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MessageA {
    pub c: BigInt,               // paillier encryption
    pub range_proof: AliceProof, // proofs (using other parties' h1,h2,N_tilde) that the plaintext is small
}

/// enumerates types of proofs Bob can use in the protocol
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum BobProofType {
    RangeProofExt(BobProofExt),
    RangeProof(BobProof),
}

/// enumerates the subtype of Bob's proof
#[derive(Debug)]
pub enum MTAMode {
    MtA,
    MtAwc,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MessageB {
    pub c: BigInt, // paillier encryption
    pub range_proof: BobProofType,
    pub b_proof: DLogProof<Secp256k1, Sha256>, // Phase 4, irrelated to MtAwc, zkp of gamma_i using Schnorr's protocol
}

impl MessageA {
    /// Creates a new `messageA` using Alice's Paillier encryption key and `dlog_statements`
    /// - other parties' `h1,h2,N_tilde`s for range proofs.
    /// If range proofs are not needed (one example is identification of aborts where we
    /// only want to reconstruct a ciphertext), `dlog_statements` can be an empty slice.
    pub fn a(
        a: &Scalar<Secp256k1>,
        alice_ek: &EncryptionKey,
        bob_dlog_statement: &DLogStatement,
    ) -> (Self, BigInt) {
        let randomness = BigInt::sample_below(&alice_ek.n);
        let m_a =
            MessageA::a_with_predefined_randomness(a, alice_ek, &randomness, bob_dlog_statement);
        (m_a, randomness)
    }

    pub fn a_with_predefined_randomness(
        a: &Scalar<Secp256k1>,
        alice_ek: &EncryptionKey,
        randomness: &BigInt,
        bob_dlog_statement: &DLogStatement,
    ) -> Self {
        let c_a = Paillier::encrypt_with_chosen_randomness(
            alice_ek,
            RawPlaintext::from(a.to_bigint()),
            &Randomness::from(randomness.clone()),
        )
        .0
        .clone()
        .into_owned();

        let alice_range_proof = AliceProof::generate(
            &a.to_bigint(),
            &c_a,
            alice_ek,
            bob_dlog_statement,
            randomness,
        );

        Self {
            c: c_a,
            range_proof: alice_range_proof,
        }
    }
}

impl MessageB {
    pub fn b(
        b: &Scalar<Secp256k1>,
        alice_ek: &EncryptionKey,
        m_a: MessageA,
        alice_dlog_statement: &DLogStatement,
        bob_dlog_statement: &DLogStatement,
        mta_mode: MTAMode,
    ) -> Outcome<(Self, Scalar<Secp256k1>, BigInt, BigInt)> {
        let beta_tag = BigInt::sample_below(&alice_ek.n);
        let randomness = BigInt::sample_below(&alice_ek.n);
        let (m_b, beta) = MessageB::b_with_predefined_randomness(
            b,
            alice_ek,
            m_a,
            &randomness,
            &beta_tag,
            alice_dlog_statement,
            bob_dlog_statement,
            mta_mode,
        ).catch_()?;

        Ok((m_b, beta, randomness, beta_tag))
    }

    pub fn b_with_predefined_randomness(
        b: &Scalar<Secp256k1>,
        alice_ek: &EncryptionKey,
        m_a: MessageA,
        randomness: &BigInt,
        beta_tag: &BigInt,
        alice_dlog_statement: &DLogStatement,
        bob_dlog_statement: &DLogStatement,
        mta_mode: MTAMode,
    ) -> Outcome<(Self, Scalar<Secp256k1>)> {
        // verify Alice's range proof
        let range_proof_verified = m_a.range_proof.verify(&m_a.c, alice_ek, bob_dlog_statement);
        assert_throw!(range_proof_verified, "InvalidProof");

        let beta_tag_fe = Scalar::<Secp256k1>::from(beta_tag);
        let c_beta_tag = Paillier::encrypt_with_chosen_randomness(
            alice_ek,
            RawPlaintext::from(beta_tag),
            &Randomness::from(randomness.clone()),
        );

        let b_bn = b.to_bigint();
        let b_c_a = Paillier::mul(
            alice_ek,
            RawCiphertext::from(m_a.c.clone()),
            RawPlaintext::from(b_bn),
        );
        let c_b = Paillier::add(alice_ek, b_c_a, c_beta_tag);
        let beta = Scalar::<Secp256k1>::zero() - &beta_tag_fe;

        let bob_range_proof = match mta_mode {
            MTAMode::MtA => BobProofType::RangeProof(
                BobProof::generate(
                    &m_a.c,
                    &c_b.0.borrow(),
                    &b, // gamma
                    &beta_tag,
                    alice_ek,
                    alice_dlog_statement,
                    &Randomness::from(randomness.clone()),
                    false,
                )
                .0,
            ),
            MTAMode::MtAwc => BobProofType::RangeProofExt(BobProofExt::generate(
                &m_a.c,
                &c_b.0.borrow(),
                &b,
                &beta_tag,
                alice_ek,
                alice_dlog_statement,
                &Randomness::from(randomness.clone()),
            )),
        };

        let dlog_proof_b = DLogProof::prove(b);

        Ok((
            Self {
                c: c_b.0.clone().into_owned(),
                range_proof: bob_range_proof,
                b_proof: dlog_proof_b,
            },
            beta,
        ))
    }

    pub fn verify_proofs_get_alpha(
        &self,
        dk: &DecryptionKey,
        m_a: MessageA,
        alice_dlog_statement: &DLogStatement,
        alice_ek: &EncryptionKey,
        X: &Point<Secp256k1>, // g^(w_i)
    ) -> Outcome<(Scalar<Secp256k1>, BigInt)> {
        let alice_share = Paillier::decrypt(dk, &RawCiphertext::from(self.c.clone()));
        let alpha = Scalar::<Secp256k1>::from(alice_share.0.as_ref());

        match &self.range_proof {
            // verify Bob's range proof
            RangeProof(bob_range_proof) => {
                let bob_range_proof_verified = bob_range_proof.verify(
                    &m_a.c,
                    &self.c,
                    alice_ek,
                    alice_dlog_statement,
                    None,
                );
                assert_throw!(bob_range_proof_verified, "InvalidProof");
            }
            // verify Bob's range proof with proof of knowing b
            RangeProofExt(bob_range_proof) => {
                let bob_range_proof_verified_knowing_b = bob_range_proof.verify(
                    &m_a.c,
                    &self.c,
                    alice_ek,
                    alice_dlog_statement,
                    X,
                );
                assert_throw!(bob_range_proof_verified_knowing_b, "InvalidProof");
            }
        };
        Ok((alpha, alice_share.0.into_owned()))
    }

    pub fn verify_b_against_public(
        public_gb: &Point<Secp256k1>,
        mta_gb: &Point<Secp256k1>,
    ) -> bool {
        public_gb == mta_gb
    }
}