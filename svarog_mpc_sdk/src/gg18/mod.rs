#![allow(non_snake_case)]
/*
    This is a modified version of `party_i.rs` in Kzen Networks' Multi-party ECDSA library
    (https://github.com/KZen-networks/multi-party-ecdsa/src/protocols/multi_party_ecdsa/gg_2018/party_i.rs)
*/

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

mod keygen;
use itertools::izip;
pub use keygen::*;
// mod keygen_mnem;
// pub use keygen_mnem::*;
// mod sign;
// pub use sign::*;
// mod hd;
// pub use hd::*;

// use centipede::juggling::proof_system::{Helgamalsegmented, Witness};
// use centipede::juggling::segmentation::Msegmentation;
use aes_gcm::{
    aead::{Aead, NewAead, Payload},
    Aes256Gcm, Nonce,
};
use rand_core::RngCore;
use xuanmi_base_support::*;

use centipede::juggling::proof_system::{Helgamalsegmented, Witness};
use centipede::juggling::segmentation::Msegmentation;
use curv::arithmetic::traits::*;
use curv::cryptographic_primitives::commitments::hash_commitment::HashCommitment;
use curv::cryptographic_primitives::commitments::traits::Commitment;
use curv::cryptographic_primitives::hashing::{Digest, DigestExt};
use curv::cryptographic_primitives::proofs::sigma_correct_homomorphic_elgamal_enc::*;
use curv::cryptographic_primitives::proofs::sigma_dlog::DLogProof;
use curv::cryptographic_primitives::secret_sharing::feldman_vss::VerifiableSS;
use curv::elliptic::curves::{Curve, Point, Scalar, Secp256k1};
use curv::BigInt;
use paillier::{
    Decrypt, DecryptionKey, EncryptionKey, KeyGeneration, Paillier, RawCiphertext, RawPlaintext,
};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::convert::TryFrom;
use zk_paillier::zkproofs::NiCorrectKeyProof;

const SECURITY: usize = 256;

#[derive(Debug)]
pub struct Parameters {
    pub threshold: u16,   //t
    pub share_count: u16, //n
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Keys<E: Curve = Secp256k1> {
    pub u_i: Scalar<E>,
    pub y_i: Point<E>,
    pub dk: DecryptionKey,
    pub ek: EncryptionKey,
    pub party_index: u16,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PartyPrivate {
    u_i: Scalar<Secp256k1>,
    x_i: Scalar<Secp256k1>,
    dk: DecryptionKey,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct KeyGenBroadcastMessage1 {
    pub e: EncryptionKey,
    pub com: BigInt,
    pub correct_key_proof: NiCorrectKeyProof,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct KeyGenDecommitMessage1 {
    pub blind_factor: BigInt,
    pub y_i: Point<Secp256k1>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SharedKeys {
    pub y: Point<Secp256k1>,
    pub x_i: Scalar<Secp256k1>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SignKeys {
    pub w_i: Scalar<Secp256k1>,
    pub g_w_i: Point<Secp256k1>,
    pub k_i: Scalar<Secp256k1>,
    pub gamma_i: Scalar<Secp256k1>,
    pub g_gamma_i: Point<Secp256k1>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SignBroadcastPhase1 {
    pub com: BigInt,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SignDecommitPhase1 {
    pub blind_factor: BigInt,
    pub g_gamma_i: Point<Secp256k1>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LocalSignature {
    pub l_i: Scalar<Secp256k1>,
    pub rho_i: Scalar<Secp256k1>,
    pub R: Point<Secp256k1>,
    pub s_i: Scalar<Secp256k1>,
    pub m: BigInt,
    pub y: Point<Secp256k1>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Phase5Com1 {
    pub com: BigInt,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Phase5Com2 {
    pub com: BigInt,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Phase5ADecom1 {
    pub V_i: Point<Secp256k1>,
    pub A_i: Point<Secp256k1>,
    pub B_i: Point<Secp256k1>,
    pub blind_factor: BigInt,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Phase5DDecom2 {
    pub u_i: Point<Secp256k1>,
    pub t_i: Point<Secp256k1>,
    pub blind_factor: BigInt,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SignatureRecid {
    pub r: Scalar<Secp256k1>,
    pub s: Scalar<Secp256k1>,
    pub recid: u8,
}

impl Keys {
    pub fn create(index: u16) -> Self {
        let u = Scalar::<Secp256k1>::random();
        let y = Point::generator() * &u;
        let (ek, dk) = Paillier::keypair().keys();

        Self {
            u_i: u,
            y_i: y,
            dk,
            ek,
            party_index: index,
        }
    }

    // we recommend using safe primes if the code is used in production
    pub fn create_safe_prime(index: u16) -> Keys {
        let u = Scalar::<Secp256k1>::random();
        let y = Point::generator() * &u;

        let (ek, dk) = Paillier::keypair_safe_primes().keys();

        Keys {
            u_i: u,
            y_i: y,
            dk,
            ek,
            party_index: index,
        }
    }
    pub fn create_from(u: Scalar<Secp256k1>, index: u16) -> Keys {
        let y = Point::generator() * &u;
        let (ek, dk) = Paillier::keypair().keys();

        Self {
            u_i: u,
            y_i: y,
            dk,
            ek,
            party_index: index,
        }
    }

    pub fn phase1_broadcast_phase3_proof_of_correct_key(
        &self,
    ) -> (KeyGenBroadcastMessage1, KeyGenDecommitMessage1) {
        let blind_factor = BigInt::sample(SECURITY);
        let correct_key_proof = NiCorrectKeyProof::proof(&self.dk, None);
        let com = HashCommitment::<Sha256>::create_commitment_with_user_defined_randomness(
            &BigInt::from_bytes(self.y_i.to_bytes(true).as_ref()),
            &blind_factor,
        );
        let bcm1 = KeyGenBroadcastMessage1 {
            e: self.ek.clone(),
            com,
            correct_key_proof,
        };
        let decom1 = KeyGenDecommitMessage1 {
            blind_factor,
            y_i: self.y_i.clone(),
        };
        (bcm1, decom1)
    }

    #[allow(clippy::type_complexity)]
    pub fn phase1_verify_com_phase3_verify_correct_key_phase2_distribute(
        &self,
        params: &Parameters,
        decom_vec: &[KeyGenDecommitMessage1],
        bc1_vec: &[KeyGenBroadcastMessage1],
    ) -> Outcome<(VerifiableSS<Secp256k1>, Vec<Scalar<Secp256k1>>, u16)> {
        // test length:
        assert_throw!(decom_vec.len() == usize::from(params.share_count));
        assert_throw!(bc1_vec.len() == usize::from(params.share_count));

        // test paillier correct key and test decommitments
        for i in 0..bc1_vec.len() {
            bc1_vec[i]
                .correct_key_proof
                .verify(&bc1_vec[i].e, zk_paillier::zkproofs::SALT_STRING)
                .catch_()?;
            let decom_correct =
                HashCommitment::<Sha256>::create_commitment_with_user_defined_randomness(
                    &BigInt::from_bytes(decom_vec[i].y_i.to_bytes(true).as_ref()),
                    &decom_vec[i].blind_factor,
                ) == bc1_vec[i].com;
            assert_throw!(decom_correct);
        }

        let (vss_scheme, secret_shares) =
            VerifiableSS::share(params.threshold, params.share_count, &self.u_i);
        Ok((vss_scheme, secret_shares.to_vec(), self.party_index))
    }

    pub fn phase2_verify_vss_construct_keypair_phase3_pok_dlog(
        &self,
        params: &Parameters,
        y_vec: &[Point<Secp256k1>],
        secret_shares_vec: &[Scalar<Secp256k1>],
        vss_scheme_vec: &[VerifiableSS<Secp256k1>],
        index: u16,
    ) -> Outcome<(SharedKeys, DLogProof<Secp256k1, Sha256>)> {
        assert_throw!(y_vec.len() == usize::from(params.share_count));
        assert_throw!(secret_shares_vec.len() == usize::from(params.share_count));
        assert_throw!(vss_scheme_vec.len() == usize::from(params.share_count));

        for i in 0..y_vec.len() {
            assert_throw!(vss_scheme_vec[i].commitments[0] == y_vec[i]);
            vss_scheme_vec[i]
                .validate_share(&secret_shares_vec[i], index)
                .map_err(|_| "ValidateShareError")
                .catch_()?;
        }

        let y: Point<Secp256k1> = y_vec.iter().sum();
        let x_i: Scalar<Secp256k1> = secret_shares_vec.iter().sum();
        let dlog_proof = DLogProof::prove(&x_i);
        Ok((SharedKeys { y, x_i }, dlog_proof))
    }

    pub fn get_commitments_to_xi(
        vss_scheme_vec: &[VerifiableSS<Secp256k1>],
    ) -> Vec<Point<Secp256k1>> {
        let len = vss_scheme_vec.len();
        (1..=u16::try_from(len).unwrap())
            .map(|i| {
                (0..len)
                    .map(|j| vss_scheme_vec[j].get_point_commitment(i))
                    .sum()
            })
            .collect::<Vec<Point<Secp256k1>>>()
    }

    pub fn update_commitments_to_xi(
        comm: &Point<Secp256k1>,
        vss_scheme: &VerifiableSS<Secp256k1>,
        index: u16,
        s: &[u16],
    ) -> Point<Secp256k1> {
        let li =
            VerifiableSS::<Secp256k1>::map_share_to_new_params(&vss_scheme.parameters, index, s);
        comm * &li
    }

    pub fn verify_dlog_proofs(
        params: &Parameters,
        dlog_proofs_vec: &[DLogProof<Secp256k1, Sha256>],
        y_vec: &[Point<Secp256k1>],
    ) -> Outcome<()> {
        assert_throw!(y_vec.len() == usize::from(params.share_count));
        assert_throw!(dlog_proofs_vec.len() == usize::from(params.share_count));

        for d in dlog_proofs_vec.iter() {
            DLogProof::verify(d).catch_()?;
        }

        Ok(())
    }
}

impl PartyPrivate {
    pub fn set_private(key: Keys, shared_key: SharedKeys) -> Self {
        Self {
            u_i: key.u_i,
            x_i: shared_key.x_i,
            dk: key.dk,
        }
    }

    pub fn y_i(&self) -> Point<Secp256k1> {
        Point::generator() * &self.u_i
    }

    pub fn decrypt(&self, ciphertext: BigInt) -> RawPlaintext {
        Paillier::decrypt(&self.dk, &RawCiphertext::from(ciphertext))
    }

    pub fn refresh_private_key(&self, factor: &Scalar<Secp256k1>, index: u16) -> Keys {
        let u: Scalar<Secp256k1> = &self.u_i + factor;
        let y = Point::generator() * &u;
        let (ek, dk) = Paillier::keypair().keys();

        Keys {
            u_i: u,
            y_i: y,
            dk,
            ek,
            party_index: index,
        }
    }

    // we recommend using safe primes if the code is used in production
    pub fn refresh_private_key_safe_prime(&self, factor: &Scalar<Secp256k1>, index: u16) -> Keys {
        let u: Scalar<Secp256k1> = &self.u_i + factor;
        let y = Point::generator() * &u;
        let (ek, dk) = Paillier::keypair_safe_primes().keys();

        Keys {
            u_i: u,
            y_i: y,
            dk,
            ek,
            party_index: index,
        }
    }

    // used for verifiable recovery
    pub fn to_encrypted_segment(
        &self,
        segment_size: usize,
        num_of_segments: usize,
        pub_ke_y: &Point<Secp256k1>,
        g: &Point<Secp256k1>,
    ) -> (Witness, Helgamalsegmented) {
        Msegmentation::to_encrypted_segments(&self.u_i, &segment_size, num_of_segments, pub_ke_y, g)
    }

    pub fn update_private_key(
        &self,
        factor_u_i: &Scalar<Secp256k1>,
        factor_x_i: &Scalar<Secp256k1>,
    ) -> Self {
        PartyPrivate {
            u_i: &self.u_i + factor_u_i,
            x_i: &self.x_i + factor_x_i,
            dk: self.dk.clone(),
        }
    }
}

impl SignKeys {
    pub fn create(
        private: &PartyPrivate,
        vss_scheme: &VerifiableSS<Secp256k1>,
        index: u16,
        s: &[u16],
    ) -> Self {
        let li =
            VerifiableSS::<Secp256k1>::map_share_to_new_params(&vss_scheme.parameters, index, s);
        let w_i = li * &private.x_i;
        let g = Point::generator();
        let g_w_i = g * &w_i;
        let gamma_i = Scalar::<Secp256k1>::random();
        let g_gamma_i = g * &gamma_i;

        Self {
            w_i,
            g_w_i,
            k_i: Scalar::<Secp256k1>::random(),
            gamma_i,
            g_gamma_i,
        }
    }

    pub fn phase1_broadcast(&self) -> (SignBroadcastPhase1, SignDecommitPhase1) {
        let blind_factor = BigInt::sample(SECURITY);
        let g = Point::generator();
        let g_gamma_i = g * &self.gamma_i;
        let com = HashCommitment::<Sha256>::create_commitment_with_user_defined_randomness(
            &BigInt::from_bytes(g_gamma_i.to_bytes(true).as_ref()),
            &blind_factor,
        );

        (
            SignBroadcastPhase1 { com },
            SignDecommitPhase1 {
                blind_factor,
                g_gamma_i: self.g_gamma_i.clone(),
            },
        )
    }

    pub fn phase2_delta_i(
        &self,
        alpha_vec: &[Scalar<Secp256k1>],
        beta_vec: &[Scalar<Secp256k1>],
    ) -> Scalar<Secp256k1> {
        assert_eq!(alpha_vec.len(), beta_vec.len());
        let ki_gamma_i = &self.k_i * &self.gamma_i;
        ki_gamma_i + alpha_vec.iter().chain(beta_vec).sum::<Scalar<Secp256k1>>()
    }

    pub fn phase2_sigma_i(
        &self,
        miu_vec: &[Scalar<Secp256k1>],
        ni_vec: &[Scalar<Secp256k1>],
    ) -> Scalar<Secp256k1> {
        assert_eq!(miu_vec.len(), ni_vec.len());
        let ki_w_i = &self.k_i * &self.w_i;
        ki_w_i + miu_vec.iter().chain(ni_vec).sum::<Scalar<Secp256k1>>()
    }

    pub fn phase3_reconstruct_delta(delta_vec: &[Scalar<Secp256k1>]) -> Scalar<Secp256k1> {
        delta_vec
            .iter()
            .sum::<Scalar<Secp256k1>>()
            .invert()
            .expect("sum of deltas is zero")
    }

    pub fn phase4(
        delta_inv: &Scalar<Secp256k1>,
        b_proof_vec: &[&DLogProof<Secp256k1, Sha256>],
        phase1_decommit_vec: Vec<SignDecommitPhase1>,
        bc1_vec: &[SignBroadcastPhase1],
    ) -> Outcome<Point<Secp256k1>> {
        // note: b_proof_vec is populated using the results
        //// from the MtAwc, which is handling the proof of knowledge verification of gamma_i such that
        //// Gamme_i = gamma_i * G in the verify_proofs_get_alpha()
        assert_throw!(b_proof_vec.len() == phase1_decommit_vec.len());
        assert_throw!(b_proof_vec.len() == bc1_vec.len());

        for i in 0..b_proof_vec.len() {
            let b_proof = b_proof_vec[i];
            let p1decom = &phase1_decommit_vec[i];
            let bc1 = &bc1_vec[i];
            assert_throw!(b_proof.pk == p1decom.g_gamma_i);
            let hash_commitment =
                HashCommitment::<Sha256>::create_commitment_with_user_defined_randomness(
                    &BigInt::from_bytes(phase1_decommit_vec[i].g_gamma_i.to_bytes(true).as_ref()),
                    &phase1_decommit_vec[i].blind_factor,
                );
            assert_throw!(hash_commitment == bc1.com);
        }

        let gamma_sum: Point<Secp256k1> = phase1_decommit_vec
            .iter()
            .map(|decom| &decom.g_gamma_i)
            .sum();

        Ok(gamma_sum * delta_inv) // R
    }
}

impl LocalSignature {
    pub fn phase5_local_sig(
        k_i: &Scalar<Secp256k1>,
        message: &BigInt,
        R: &Point<Secp256k1>,
        sigma_i: &Scalar<Secp256k1>,
        pubkey: &Point<Secp256k1>,
    ) -> Self {
        let m_fe = Scalar::<Secp256k1>::from(message);
        let r = Scalar::<Secp256k1>::from(
            &R.x_coord()
                .unwrap()
                .mod_floor(Scalar::<Secp256k1>::group_order()),
        );
        let s_i = m_fe * k_i + r * sigma_i;
        let l_i = Scalar::<Secp256k1>::random();
        let rho_i = Scalar::<Secp256k1>::random();
        Self {
            l_i,
            rho_i,
            R: R.clone(),
            s_i,
            m: message.clone(),
            y: pubkey.clone(),
        }
    }

    pub fn phase5a_broadcast_5b_zkproof(
        &self,
    ) -> (
        Phase5Com1,
        Phase5ADecom1,
        HomoELGamalProof<Secp256k1, Sha256>,
        DLogProof<Secp256k1, Sha256>,
    ) {
        let blind_factor = BigInt::sample(SECURITY);
        let g = Point::generator();
        let A_i = g * &self.rho_i;
        let l_i_rho_i = &self.l_i * &self.rho_i;
        let B_i = g * l_i_rho_i;
        let V_i = &self.R * &self.s_i + g * &self.l_i;
        let input_hash = Sha256::new()
            .chain_points([&V_i, &A_i, &B_i])
            .result_bigint();
        let com = HashCommitment::<Sha256>::create_commitment_with_user_defined_randomness(
            &input_hash,
            &blind_factor,
        );
        let witness = HomoElGamalWitness {
            r: self.l_i.clone(),
            x: self.s_i.clone(),
        };
        let delta = HomoElGamalStatement {
            G: A_i.clone(),
            H: self.R.clone(),
            Y: g.to_point(),
            D: V_i.clone(),
            E: B_i.clone(),
        };
        let dlog_proof_rho = DLogProof::prove(&self.rho_i);
        let proof = HomoELGamalProof::prove(&witness, &delta);

        (
            Phase5Com1 { com },
            Phase5ADecom1 {
                V_i,
                A_i,
                B_i,
                blind_factor,
            },
            proof,
            dlog_proof_rho,
        )
    }

    pub fn phase5c(
        &self,
        decom_vec: &[Phase5ADecom1],
        com_vec: &[Phase5Com1],
        elgamal_proofs: &[HomoELGamalProof<Secp256k1, Sha256>],
        dlog_proofs_rho: &[DLogProof<Secp256k1, Sha256>],
        v_i: &Point<Secp256k1>,
        R: &Point<Secp256k1>,
    ) -> Outcome<(Phase5Com2, Phase5DDecom2)> {
        assert_throw!(decom_vec.len() == com_vec.len());
        assert_throw!(decom_vec.len() == elgamal_proofs.len());
        assert_throw!(decom_vec.len() == dlog_proofs_rho.len());

        let g = Point::generator();
        for i in 0..decom_vec.len() {
            let decom = &decom_vec[i];
            let com = &com_vec[i];
            let elgamal_proof = &elgamal_proofs[i];
            let dlog_proof_rho = &dlog_proofs_rho[i];

            let delta = HomoElGamalStatement {
                G: decom.A_i.clone(),
                H: R.clone(),
                Y: g.to_point(),
                D: decom.V_i.clone(),
                E: decom.B_i.clone(),
            };
            let input_hash = Sha256::new()
                .chain_points([&decom.V_i, &decom.A_i, &decom.B_i])
                .result_bigint();
            let hash_commitment =
                HashCommitment::<Sha256>::create_commitment_with_user_defined_randomness(
                    &input_hash,
                    &decom_vec[i].blind_factor,
                );
            assert_throw!(hash_commitment == com.com);
            elgamal_proof.verify(&delta).catch_()?;
            DLogProof::verify(dlog_proof_rho).catch_()?;
        }

        let v_iter = (0..com_vec.len()).map(|i| &decom_vec[i].V_i);
        let a_iter = (0..com_vec.len()).map(|i| &decom_vec[i].A_i);

        let v = v_i + v_iter.sum::<Point<Secp256k1>>();
        // V = -mG -ry - sum (vi)
        let a: Point<Secp256k1> = a_iter.sum();

        let r = Scalar::<Secp256k1>::from(
            &self
                .R
                .x_coord()
                .ifnone_()?
                .mod_floor(Scalar::<Secp256k1>::group_order()),
        );
        let yr = &self.y * r;
        let g = Point::generator();
        let m_fe = Scalar::<Secp256k1>::from(&self.m);
        let gm = g * m_fe;
        let v = v - &gm - &yr;
        let u_i = v * &self.rho_i;
        let t_i = a * &self.l_i;
        let input_hash = Sha256::new().chain_points([&u_i, &t_i]).result_bigint();
        let blind_factor = BigInt::sample(SECURITY);
        let com = HashCommitment::<Sha256>::create_commitment_with_user_defined_randomness(
            &input_hash,
            &blind_factor,
        );

        Ok((
            Phase5Com2 { com },
            Phase5DDecom2 {
                u_i,
                t_i,
                blind_factor,
            },
        ))
    }

    pub fn phase5d(
        &self,
        decom_vec2: &[Phase5DDecom2],
        com_vec2: &[Phase5Com2],
        decom_vec1: &[Phase5ADecom1],
    ) -> Outcome<Scalar<Secp256k1>> {
        assert_throw!(decom_vec2.len() == decom_vec1.len());
        assert_throw!(decom_vec2.len() == com_vec2.len());

        for (decom2, com2) in izip!(decom_vec2, com_vec2) {
            let input_hash = Sha256::new()
                .chain_points([&decom2.u_i, &decom2.t_i])
                .result_bigint();
            let hash_commitment =
                HashCommitment::<Sha256>::create_commitment_with_user_defined_randomness(
                    &input_hash,
                    &decom2.blind_factor,
                );
            assert_throw!(hash_commitment == com2.com, "invalid com");
        }

        let t_iter = decom_vec2.iter().map(|decom| &decom.t_i);
        let u_iter = decom_vec2.iter().map(|decom| &decom.u_i);
        let b_iter = decom_vec1.iter().map(|decom| &decom.B_i);

        let g = Point::generator();
        let biased_sum_tb = g + t_iter.chain(b_iter).sum::<Point<Secp256k1>>();
        let biased_sum_tb_minus_u = biased_sum_tb - u_iter.sum::<Point<Secp256k1>>();

        assert_throw!(*g.as_point() == biased_sum_tb_minus_u, "invalid key");
        Ok(self.s_i.clone())
    }

    pub fn output_signature(&self, s_vec: &[Scalar<Secp256k1>]) -> Outcome<SignatureRecid> {
        let mut s = &self.s_i + s_vec.iter().sum::<Scalar<Secp256k1>>();
        let s_bn = s.to_bigint();

        let r = Scalar::<Secp256k1>::from(
            &self
                .R
                .x_coord()
                .ifnone_()?
                .mod_floor(Scalar::<Secp256k1>::group_order()),
        );
        let ry: BigInt = self
            .R
            .y_coord()
            .ifnone_()?
            .mod_floor(Scalar::<Secp256k1>::group_order());

        /*
         Calculate recovery id - it is not possible to compute the public key out of the signature
         itself. Recovery id is used to enable extracting the public key uniquely.
         1. id = R.y & 1
         2. if (s > curve.q / 2) id = id ^ 1
        */
        let is_ry_odd = ry.test_bit(0);
        let mut recid = if is_ry_odd { 1 } else { 0 };
        let s_tag_bn = Scalar::<Secp256k1>::group_order() - &s_bn;
        if s_bn > s_tag_bn {
            s = Scalar::<Secp256k1>::from(&s_tag_bn);
            recid ^= 1;
        }
        let sig = SignatureRecid { r, s, recid };
        verify(&sig, &self.y, &self.m).catch_()?;
        Ok(sig)
    }
}

pub fn verify(sig: &SignatureRecid, y: &Point<Secp256k1>, message: &BigInt) -> Outcome<()> {
    let b = sig.s.invert().ifnone_()?;
    let a = Scalar::<Secp256k1>::from(message);
    let u1 = a * &b;
    let u2 = &sig.r * &b;

    let g = Point::generator();
    let gu1 = g * u1;
    let yu2 = y * &u2;
    // can be faster using shamir trick

    let verification = sig.r
        == Scalar::<Secp256k1>::from(
            &(gu1 + yu2)
                .x_coord()
                .ifnone_()?
                .mod_floor(Scalar::<Secp256k1>::group_order()),
        );
    assert_throw!(verification, "invalid signature");
    Ok(())
}

#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
pub struct AEAD {
    pub ciphertext: Vec<u8>,
    pub tag: Vec<u8>,
}

pub fn aes_encrypt(key: &[u8], plaintext: &[u8]) -> Outcome<AEAD> {
    let mut full_length_key: [u8; 32] = [0; 32];
    full_length_key[(32 - key.len())..].copy_from_slice(key); // pad key with zeros

    let aes_key = aes_gcm::Key::from_slice(full_length_key.as_slice());
    let cipher = Aes256Gcm::new(aes_key);

    let mut _buf = [0u8; 12];
    let nonce = {
        rand::rngs::OsRng.fill_bytes(&mut _buf); // provided by Rng trait
        Nonce::from_slice(_buf.as_slice())
    };

    // reserve for later changes when a non-empty aad could be imported
    let aad: Vec<u8> = std::iter::repeat(0).take(16).collect();
    let payload = Payload {
        msg: plaintext,
        aad: aad.as_slice(),
    };

    let ciphertext = cipher
        .encrypt(nonce, payload)
        .catch("AesGcmException", "")?;

    Ok(AEAD {
        ciphertext,
        tag: nonce.to_vec(),
    })
}

pub fn aes_decrypt(key: &[u8], aead_pack: &AEAD) -> Outcome<Vec<u8>> {
    let mut full_length_key: [u8; 32] = [0; 32];
    full_length_key[(32 - key.len())..].copy_from_slice(key); // Pad key with zeros

    let aes_key = aes_gcm::Key::from_slice(full_length_key.as_slice());
    let nonce = Nonce::from_slice(&aead_pack.tag);
    let gcm = Aes256Gcm::new(aes_key);

    // reserve for later changes when a non-empty aad could be imported
    let aad: Vec<u8> = std::iter::repeat(0).take(16).collect();
    let payload = Payload {
        msg: aead_pack.ciphertext.as_slice(),
        aad: aad.as_slice(),
    };

    // NOTE: no error reported but return a value NONE when decrypt key is wrong
    let out = gcm.decrypt(nonce, payload).catch("AesGcmException", "")?;
    Ok(out)
}
