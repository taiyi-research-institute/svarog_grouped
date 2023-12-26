#![allow(non_snake_case)]

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

use std::collections::{HashMap, HashSet};

use super::feldman_vss::VerifiableSS;
use crate::{assert_throw, exception::*};
use curv::arithmetic::traits::*;
use curv::cryptographic_primitives::commitments::hash_commitment::HashCommitment;
use curv::cryptographic_primitives::commitments::traits::Commitment;
use curv::cryptographic_primitives::hashing::{Digest, DigestExt};
use curv::cryptographic_primitives::proofs::sigma_correct_homomorphic_elgamal_enc::*;
use curv::cryptographic_primitives::proofs::sigma_dlog::DLogProof;
use curv::elliptic::curves::{Curve, Point, Scalar, Secp256k1};
use curv::BigInt;
use paillier::{
    Decrypt, DecryptionKey, EncryptionKey, KeyGeneration, Paillier, RawCiphertext, RawPlaintext,
};
use sha2::Sha256;
use zk_paillier::zkproofs::NiCorrectKeyProof;

use serde::{Deserialize, Serialize};

const SECURITY: usize = 256;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Keys<E: Curve = Secp256k1> {
    pub u_i: Scalar<E>,
    pub y_i: Point<E>,
    pub dk: DecryptionKey,
    pub ek: EncryptionKey,
    pub member_id: u16,
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
pub struct SharedKeyPair {
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
    pub fn create_casually(member_id: u16) -> Keys {
        let u_i = Scalar::<Secp256k1>::random();
        let y_i = Point::<Secp256k1>::generator() * &u_i;

        let (ek, dk) = Paillier::keypair().keys();

        Self {
            u_i,
            y_i,
            dk,
            ek,
            member_id,
        }
    }

    pub fn create_casually_from(u: &Scalar<Secp256k1>, member_id: u16) -> Keys {
        let y = Point::generator() * u;
        let (ek, dk) = Paillier::keypair().keys();

        Self {
            u_i: u.clone(),
            y_i: y,
            dk,
            ek,
            member_id,
        }
    }

    pub fn create_safely(member_id: u16) -> Keys {
        let u_i = Scalar::<Secp256k1>::random();
        let y_i = Point::<Secp256k1>::generator() * &u_i;

        let (ek, dk) = Paillier::keypair_safe_primes().keys();

        Self {
            u_i,
            y_i,
            dk,
            ek,
            member_id,
        }
    }

    pub fn create_safely_from(u: &Scalar<Secp256k1>, member_id: u16) -> Keys {
        let y = Point::generator() * u;
        let (ek, dk) = Paillier::keypair_safe_primes().keys();

        Self {
            u_i: u.clone(),
            y_i: y,
            dk,
            ek,
            member_id,
        }
    }

    pub fn phase1_broadcast_phase3_proof_of_correct_key(
        &self,
    ) -> (KeyGenBroadcastMessage1, KeyGenDecommitMessage1) {
        let blind_factor: BigInt = BigInt::sample(SECURITY);
        let correct_key_proof: NiCorrectKeyProof = NiCorrectKeyProof::proof(&self.dk, None);
        let com: BigInt = HashCommitment::<Sha256>::create_commitment_with_user_defined_randomness(
            &BigInt::from_bytes(self.y_i.to_bytes(true).as_ref()),
            &blind_factor,
        );
        let bc1 = KeyGenBroadcastMessage1 {
            e: self.ek.clone(),
            com,
            correct_key_proof,
        };
        let decom1 = KeyGenDecommitMessage1 {
            blind_factor,
            y_i: self.y_i.clone(),
        };
        (bc1, decom1)
    }

    pub fn phase1_verify_com_phase3_verify_correct_key_phase2_distribute(
        &self,
        th: u16,
        com_kv: &HashMap<u16, KeyGenBroadcastMessage1>,
        decom_kv: &HashMap<u16, KeyGenDecommitMessage1>,
    ) -> Outcome<(VerifiableSS<Secp256k1>, HashMap<u16, Scalar<Secp256k1>>)> {
        for (member_id, bc_i) in com_kv.iter() {
            let decom_i = decom_kv.get(member_id).ifnone_()?;
            bc_i.correct_key_proof
                .verify(&bc_i.e, zk_paillier::zkproofs::SALT_STRING)
                .catch_()?;
            let hashcom = HashCommitment::<Sha256>::create_commitment_with_user_defined_randomness(
                &BigInt::from_bytes(decom_i.y_i.to_bytes(true).as_ref()),
                &decom_i.blind_factor,
            );
            assert_throw!(hashcom == bc_i.com);
        }
        let keygen_members: HashSet<u16> = com_kv.keys().cloned().collect();
        let (vss_scheme, secret_shares) =
            VerifiableSS::share(th, &self.u_i, &keygen_members).catch_()?;
        let secret_shares = secret_shares.shares;
        Ok((vss_scheme, secret_shares))
    }

    pub fn phase2_verify_vss_construct_keypair_phase3_pok_dlog(
        &self,
        y_kv: &HashMap<u16, Point<Secp256k1>>,
        secret_shares_kv: &HashMap<u16, Scalar<Secp256k1>>,
        vss_scheme_kv: &HashMap<u16, VerifiableSS<Secp256k1>>,
    ) -> Outcome<(SharedKeyPair, DLogProof<Secp256k1, Sha256>)> {
        for (member_id, y_i) in y_kv.iter() {
            let x_i = secret_shares_kv.get(member_id).ifnone_()?;
            let vss_i: &VerifiableSS<Secp256k1> = vss_scheme_kv.get(member_id).ifnone_()?;
            vss_i.validate_share(x_i, self.member_id).catch_()?;
            assert_throw!(&vss_i.commitments[0] == y_i);
        }
        let y: Point<Secp256k1> = y_kv.values().sum();
        let x_i: Scalar<Secp256k1> = secret_shares_kv.values().sum();
        let dlog_proof: DLogProof<Secp256k1, Sha256> = DLogProof::prove(&x_i);
        Ok((SharedKeyPair { y, x_i }, dlog_proof))
    }

    pub fn get_commitments_to_xi(
        vss_scheme_kv: &HashMap<u16, VerifiableSS<Secp256k1>>,
    ) -> Outcome<HashMap<u16, Point<Secp256k1>>> {
        let mut res = HashMap::new();
        for i in vss_scheme_kv.keys() {
            let mut point: Point<Secp256k1> = Point::zero();
            for j in vss_scheme_kv.keys() {
                let vss_j: &VerifiableSS<Secp256k1> = vss_scheme_kv.get(j).ifnone_()?;
                point = point + vss_j.get_point_commitment(*i).catch_()?;
            }
            res.insert(*i, point);
        }
        Ok(res)
    }

    pub fn update_commitments_to_xi(
        member_id: u16,
        comm: &Point<Secp256k1>,
        key_providers: &HashSet<u16>,
    ) -> Outcome<Point<Secp256k1>> {
        let li: Scalar<Secp256k1> =
            VerifiableSS::map_share_to_new_params(member_id, &key_providers).catch_()?;
        Ok(comm * &li)
    }

    pub fn verify_dlog_proofs(
        dlog_proofs_kv: &HashMap<u16, DLogProof<Secp256k1, Sha256>>,
    ) -> Outcome<()> {
        for proof in dlog_proofs_kv.values() {
            DLogProof::verify(proof).catch_()?;
        }
        Ok(())
    }
}

impl PartyPrivate {
    pub fn set_private(key: Keys, shared_key: SharedKeyPair) -> Self {
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
        member_id: u16,
        sign_mates: &HashSet<u16>,
    ) -> Outcome<Self> {
        // here calls the Lagrange interpolation
        let li =
            VerifiableSS::<Secp256k1>::map_share_to_new_params(member_id, sign_mates).catch_()?;
        let w_i = li * &private.x_i;
        let g_w_i = Point::generator() * &w_i;
        let gamma_i = Scalar::<Secp256k1>::random();
        let g_gamma_i = Point::generator() * &gamma_i;

        let res = Self {
            w_i,
            g_w_i,
            k_i: Scalar::<Secp256k1>::random(),
            gamma_i,
            g_gamma_i,
        };
        Ok(res)
    }

    pub fn phase1_broadcast(&self) -> (SignBroadcastPhase1, SignDecommitPhase1) {
        let blind_factor = BigInt::sample(SECURITY);
        let g_gamma_i = Point::generator() * &self.gamma_i;
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
        alpha_kv: &HashMap<u16, Scalar<Secp256k1>>,
        beta_kv: &HashMap<u16, Scalar<Secp256k1>>,
    ) -> Outcome<Scalar<Secp256k1>> {
        let mut ki_gamma_i = &self.k_i * &self.gamma_i;
        for (member_id, alpha_i) in alpha_kv.iter() {
            let beta_i = beta_kv.get(member_id).ifnone_()?;
            ki_gamma_i = ki_gamma_i + alpha_i + beta_i;
        }
        Ok(ki_gamma_i)
    }

    pub fn phase2_sigma_i(
        &self,
        miu_kv: &HashMap<u16, Scalar<Secp256k1>>,
        ni_kv: &HashMap<u16, Scalar<Secp256k1>>,
    ) -> Outcome<Scalar<Secp256k1>> {
        let mut ki_w_i = &self.k_i * &self.w_i;
        for (member_id, miu_i) in miu_kv.iter() {
            let ni_i = ni_kv.get(member_id).ifnone_()?;
            ki_w_i = ki_w_i + miu_i + ni_i;
        }
        Ok(ki_w_i)
    }

    pub fn phase3_reconstruct_delta(
        delta_kv: &HashMap<u16, Scalar<Secp256k1>>,
    ) -> Outcome<Scalar<Secp256k1>> {
        let mut res: Scalar<Secp256k1> = delta_kv.values().sum();
        res = res
            .invert()
            .ifnone("AlgorithmException", "Sum of deltas is 0")?;
        Ok(res)
    }

    pub fn phase4(
        delta_inv: &Scalar<Secp256k1>,
        b_proof_kv: &HashMap<u16, &DLogProof<Secp256k1, Sha256>>,
        phase1_decom_kv: &HashMap<u16, SignDecommitPhase1>,
        bc1_kv: &HashMap<u16, SignBroadcastPhase1>,
    ) -> Outcome<Point<Secp256k1>> {
        // NOTE: b_proof_vec is populated using the results from the MtAwc,
        //// which is handling the proof of knowledge verification of gamma_i,
        //// such that `Gamma_i == gamma_i * G` in the verify_proofs_get_alpha()
        for (member_id, b_proof_i) in b_proof_kv.iter() {
            let phase1_decom_i = phase1_decom_kv.get(member_id).ifnone_()?;
            assert_throw!(b_proof_i.pk == phase1_decom_i.g_gamma_i);
            let bc1_i = bc1_kv.get(member_id).ifnone_()?;
            let hash_comm =
                HashCommitment::<Sha256>::create_commitment_with_user_defined_randomness(
                    &BigInt::from_bytes(phase1_decom_i.g_gamma_i.to_bytes(true).as_ref()),
                    &phase1_decom_i.blind_factor,
                );
            assert_throw!(bc1_i.com == hash_comm)
        }

        let mut gamma_sum: Point<Secp256k1> = Point::zero();
        for decom_i in phase1_decom_kv.values() {
            gamma_sum = gamma_sum + &decom_i.g_gamma_i
        }
        Ok(gamma_sum * delta_inv)
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
        decom_kv: &HashMap<u16, Phase5ADecom1>,
        com_kv: &HashMap<u16, Phase5Com1>,
        elgamal_proof_kv: &HashMap<u16, HomoELGamalProof<Secp256k1, Sha256>>,
        dlog_proof_rho_kv: &HashMap<u16, DLogProof<Secp256k1, Sha256>>,
        v_i: &Point<Secp256k1>,
        R: &Point<Secp256k1>,
    ) -> Outcome<(Phase5Com2, Phase5DDecom2)> {
        let g = Point::generator();
        for (member_id, com_i) in com_kv.iter() {
            let decom_i = decom_kv.get(member_id).ifnone_()?;
            let elga_i = elgamal_proof_kv.get(member_id).ifnone_()?;
            let dlog_i = dlog_proof_rho_kv.get(member_id).ifnone_()?;

            let delta = HomoElGamalStatement {
                G: decom_i.A_i.clone(),
                H: R.clone(),
                Y: g.to_point(),
                D: decom_i.V_i.clone(),
                E: decom_i.B_i.clone(),
            };

            let input_hash: BigInt = Sha256::new()
                .chain_points([&decom_i.V_i, &decom_i.A_i, &decom_i.B_i])
                .result_bigint();
            let hashcom = HashCommitment::<Sha256>::create_commitment_with_user_defined_randomness(
                &input_hash,
                &decom_i.blind_factor,
            );
            assert_throw!(com_i.com == hashcom);

            elga_i.verify(&delta).catch_()?;
            DLogProof::verify(dlog_i).catch_()?;
        }

        let mut v = v_i.clone();
        let mut a = Point::<Secp256k1>::zero();
        for decom_i in decom_kv.values() {
            v = v + &decom_i.V_i;
            a = a + &decom_i.A_i;
        }

        let r = Scalar::<Secp256k1>::from(
            &self
                .R
                .x_coord()
                .ifnone_()?
                .mod_floor(Scalar::<Secp256k1>::group_order()),
        );
        let yr = &self.y * r;
        let m_fe = Scalar::<Secp256k1>::from(&self.m);
        let gm = Point::generator() * m_fe;
        let v = v - &gm - &yr;
        let u_i = v * &self.rho_i;
        let t_i = a * &self.l_i;
        let input_hash = Sha256::new().chain_points([&u_i, &t_i]).result_bigint();
        let blind_factor = BigInt::sample(SECURITY);
        let com = HashCommitment::<Sha256>::create_commitment_with_user_defined_randomness(
            &input_hash,
            &blind_factor,
        );
        let res = (
            Phase5Com2 { com },
            Phase5DDecom2 {
                u_i,
                t_i,
                blind_factor,
            },
        );
        Ok(res)
    }

    pub fn phase5d(
        &self,
        decom2_kv: &HashMap<u16, Phase5DDecom2>,
        com2_kv: &HashMap<u16, Phase5Com2>,
        decom1_kv: &HashMap<u16, Phase5ADecom1>,
    ) -> Outcome<Scalar<Secp256k1>> {
        for (member_id, com2_i) in com2_kv.iter() {
            let decom2_i = decom2_kv.get(member_id).ifnone_()?;
            let input_hash = Sha256::new()
                .chain_points([&decom2_i.u_i, &decom2_i.t_i])
                .result_bigint();
            let hashcom = HashCommitment::<Sha256>::create_commitment_with_user_defined_randomness(
                &input_hash,
                &decom2_i.blind_factor,
            );
            assert_throw!(hashcom == com2_i.com);
        }
        let generator = Point::<Secp256k1>::generator().to_point();
        let mut biased_sum_tb = generator.clone();
        for decom2_i in decom2_kv.values() {
            biased_sum_tb = biased_sum_tb + &decom2_i.t_i;
        }
        for decom1_i in decom1_kv.values() {
            biased_sum_tb = biased_sum_tb + &decom1_i.B_i;
        }
        let mut biased_sum_tb_minus_u = biased_sum_tb.clone();
        for decom2_i in decom2_kv.values() {
            biased_sum_tb_minus_u = biased_sum_tb_minus_u - &decom2_i.u_i;
        }
        assert_throw!(biased_sum_tb_minus_u == generator);
        Ok(self.s_i.clone())
    }

    pub fn output_signature(
        &self,
        s_kv: &HashMap<u16, Scalar<Secp256k1>>,
    ) -> Outcome<SignatureRecid> {
        let mut s: Scalar<Secp256k1> = &self.s_i + s_kv.values().sum::<Scalar<Secp256k1>>();
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

    let gu1 = Point::generator() * u1;
    let yu2 = y * &u2;
    // can be faster using shamir trick

    let right = Scalar::<Secp256k1>::from(
        &(gu1 + yu2)
            .x_coord()
            .ifnone_()?
            .mod_floor(Scalar::<Secp256k1>::group_order()),
    );

    assert_throw!(sig.r == right);
    Ok(())
}
