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

    MtA is described in https://eprint.iacr.org/2019/114.pdf section 3
*/

use std::collections::HashMap;

use super::multi_party_ecdsa::PartyPrivate;
use super::range_proof::AliceProof;
use crate::{exception::*, assert_throw};
use curv::arithmetic::traits::Samplable;
use curv::cryptographic_primitives::proofs::sigma_dlog::DLogProof;
use curv::elliptic::curves::{secp256_k1::Secp256k1, Point, Scalar};
use curv::BigInt;
use paillier::traits::EncryptWithChosenRandomness;
use paillier::{Add, Decrypt, Mul};
use paillier::{DecryptionKey, EncryptionKey, Paillier, Randomness, RawCiphertext, RawPlaintext};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use zk_paillier::zkproofs::DLogStatement;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MessageA {
    pub c: BigInt,                              // paillier encryption
    pub range_proofs: HashMap<u16, AliceProof>, // proofs (using other parties' h1,h2,N_tilde) that the plaintext is small
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MessageB {
    pub c: BigInt, // paillier encryption
    pub b_proof: DLogProof<Secp256k1, Sha256>,
    pub beta_tag_proof: DLogProof<Secp256k1, Sha256>,
}

impl MessageA {
    /// Creates a new `messageA` using Alice's Paillier encryption key and `dlog_statements`
    /// - other parties' `h1,h2,N_tilde`s for range proofs.
    /// If range proofs are not needed (one example is identification of aborts where we
    /// only want to reconstruct a ciphertext), `dlog_statements` can be an empty slice.
    pub fn a(
        a: &Scalar<Secp256k1>,
        alice_ek: &EncryptionKey,
        dlog_stmt_kv: &HashMap<u16, DLogStatement>,
    ) -> (Self, BigInt) {
        let randomness = BigInt::sample_below(&alice_ek.n);
        let m_a = MessageA::a_with_predefined_randomness(a, alice_ek, &randomness, dlog_stmt_kv);
        (m_a, randomness)
    }

    pub fn a_with_predefined_randomness(
        a: &Scalar<Secp256k1>,
        alice_ek: &EncryptionKey,
        randomness: &BigInt,
        dlog_stmt_kv: &HashMap<u16, DLogStatement>,
    ) -> Self {
        let c = Paillier::encrypt_with_chosen_randomness(
            alice_ek,
            RawPlaintext::from(a.to_bigint()),
            &Randomness::from(randomness.clone()),
        )
        .0
        .clone()
        .into_owned();

        let mut range_proofs = HashMap::new();
        for (member_id, dlog_stmt) in dlog_stmt_kv.iter() {
            let alice_range_proof =
                AliceProof::generate(&a.to_bigint(), &c, alice_ek, dlog_stmt, randomness);
            range_proofs.insert(*member_id, alice_range_proof);
        }

        Self { c, range_proofs }
    }
}

impl MessageB {
    pub fn b(
        b: &Scalar<Secp256k1>,
        alice_ek: &EncryptionKey,
        m_a: MessageA,
        dlog_stmt_kv: &HashMap<u16, DLogStatement>,
    ) -> Outcome<(Self, Scalar<Secp256k1>, BigInt, BigInt)> {
        let beta_tag = BigInt::sample_below(&alice_ek.n);
        let randomness = BigInt::sample_below(&alice_ek.n);
        let (m_b, beta) = MessageB::b_with_predefined_randomness(
            b,
            alice_ek,
            m_a,
            &randomness,
            &beta_tag,
            dlog_stmt_kv,
        )?;

        Ok((m_b, beta, randomness, beta_tag))
    }

    pub fn b_with_predefined_randomness(
        b: &Scalar<Secp256k1>,
        alice_ek: &EncryptionKey,
        m_a: MessageA,
        randomness: &BigInt,
        beta_tag: &BigInt,
        dlog_stmt_kv: &HashMap<u16, DLogStatement>,
    ) -> Outcome<(Self, Scalar<Secp256k1>)> {
        assert_throw!(m_a.range_proofs.len() == dlog_stmt_kv.len());
        for (member_id, dlog_stmt) in dlog_stmt_kv.iter() {
            let alice_proof = m_a.range_proofs.get(member_id).ifnone_()?;
            let alice_proof_verified = alice_proof.verify(&m_a.c, alice_ek, dlog_stmt);
            assert_throw!(alice_proof_verified);
        }

        let beta_tag_fe = Scalar::<Secp256k1>::from(beta_tag);
        let c_beta_tag = Paillier::encrypt_with_chosen_randomness(
            alice_ek,
            RawPlaintext::from(beta_tag),
            &Randomness::from(randomness.clone()),
        );

        let b_bn = b.to_bigint();
        let b_c_a = Paillier::mul(
            alice_ek,
            RawCiphertext::from(m_a.c),
            RawPlaintext::from(b_bn),
        );
        let c_b = Paillier::add(alice_ek, b_c_a, c_beta_tag);
        let beta = Scalar::<Secp256k1>::zero() - &beta_tag_fe;
        let dlog_proof_b = DLogProof::prove(b);
        let dlog_proof_beta_tag = DLogProof::prove(&beta_tag_fe);

        Ok((
            Self {
                c: c_b.0.clone().into_owned(),
                b_proof: dlog_proof_b,
                beta_tag_proof: dlog_proof_beta_tag,
            },
            beta,
        ))
    }

    pub fn verify_proofs_get_alpha(
        &self,
        dk: &DecryptionKey,
        a: &Scalar<Secp256k1>,
    ) -> Outcome<(Scalar<Secp256k1>, BigInt)> {
        let alice_share = Paillier::decrypt(dk, &RawCiphertext::from(self.c.clone()));
        let g = Point::generator();
        let alpha = Scalar::<Secp256k1>::from(alice_share.0.as_ref());
        let g_alpha = g * &alpha;
        let ba_btag = &self.b_proof.pk * a + &self.beta_tag_proof.pk;
        DLogProof::verify(&self.b_proof).catch_()?;
        DLogProof::verify(&self.beta_tag_proof).catch_()?;
        assert_throw!(ba_btag == g_alpha);
        Ok((alpha, alice_share.0.into_owned()))
    }

    //  another version, supporting PartyPrivate therefore binding mta to gg18.
    //  with the regular version mta can be used in general
    pub fn verify_proofs_get_alpha_gg18(
        &self,
        private: &PartyPrivate,
        a: &Scalar<Secp256k1>,
    ) -> Outcome<Scalar<Secp256k1>> {
        let alice_share = private.decrypt(self.c.clone());
        let g = Point::generator();
        let alpha = Scalar::<Secp256k1>::from(alice_share.0.as_ref());
        let g_alpha = g * &alpha;
        let ba_btag = &self.b_proof.pk * a + &self.beta_tag_proof.pk;
        DLogProof::verify(&self.b_proof).catch_()?;
        DLogProof::verify(&self.beta_tag_proof).catch_()?;
        assert_throw!(ba_btag == g_alpha);
        Ok(alpha)
    }

    pub fn verify_b_against_public(
        public_gb: &Point<Secp256k1>,
        mta_gb: &Point<Secp256k1>,
    ) -> bool {
        public_gb == mta_gb
    }
}
