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

use std::convert::TryFrom;

// use centipede::juggling::proof_system::{Helgamalsegmented, Witness};
// use centipede::juggling::segmentation::Msegmentation;
use curv::{
    arithmetic::traits::*,
    cryptographic_primitives::{
        commitments::{hash_commitment::HashCommitment, traits::Commitment},
        hashing::{Digest, DigestExt},
        proofs::{sigma_correct_homomorphic_elgamal_enc::*, sigma_dlog::DLogProof},
        secret_sharing::feldman_vss::VerifiableSS,
    },
    elliptic::curves::{Curve, Point, Scalar, Secp256k1},
    BigInt,
};
use paillier::{
    Decrypt, DecryptionKey, EncryptionKey, KeyGeneration, Paillier, RawCiphertext, RawPlaintext,
};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use xuanmi_base_support::*;
use zk_paillier::zkproofs::{DLogStatement, NiCorrectKeyProof};

use super::paillier_proof::{NSFProof, PaillierBlumModProof};

const SECURITY: usize = 256;
const L: u32 = 256; // N0 = pq, where -sqrt(N0) * 2^l < p,q < sqrt(N0) * 2^l

#[derive(Clone, Debug)]
pub struct Parameters {
    pub threshold: u16,   //t
    pub share_count: u16, //n
}

// by default, share tuples are (inner, outer)
// i.e., (inner_share, outer_share)
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Keys<E: Curve = Secp256k1> {
    pub u_i: (Scalar<E>, Scalar<E>),
    pub y_i: (Point<E>, Point<E>), //g_u_i
    pub dk: DecryptionKey,
    pub ek: EncryptionKey,
    pub party_index: u16,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PartyPrivate {
    u_i: (Scalar<Secp256k1>, Scalar<Secp256k1>),
    x_i: (Scalar<Secp256k1>, Scalar<Secp256k1>),
    dk: DecryptionKey,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct KeyGenBroadcastMessage1 {
    pub e: EncryptionKey,
    pub com: (BigInt, BigInt),
    // pub correct_key_proof: NiCorrectKeyProof,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct KeyGenDecommitMessage1 {
    pub blind_factor: (BigInt, BigInt),
    pub y_i: (Point<Secp256k1>, Point<Secp256k1>),
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PaillierKeyProofs {
    pub correct_key_proof: NiCorrectKeyProof,
    pub pblum_modulus_proof: PaillierBlumModProof,
    pub no_small_factor_proof: NSFProof,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SharedKeys {
    pub y: Point<Secp256k1>,
    pub x_i: (Scalar<Secp256k1>, Scalar<Secp256k1>),
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
        let u = (Scalar::<Secp256k1>::random(), Scalar::<Secp256k1>::random());
        let y = (Point::generator() * &u.0, Point::generator() * &u.1);
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
    pub fn create_with_safe_prime(index: u16) -> Keys {
        let u = (Scalar::<Secp256k1>::random(), Scalar::<Secp256k1>::random());
        let y = (Point::generator() * &u.0, Point::generator() * &u.1);

        let (mut ek, mut dk) = Paillier::keypair_safe_primes().keys();
        let mut bound = ek.n.sqrt() * BigInt::from(2).pow(L);
        while dk.p <= -(&bound) || dk.p >= bound || dk.q <= -(&bound) || dk.q >= bound {
            (ek, dk) = Paillier::keypair_safe_primes().keys();
            bound = ek.n.sqrt() * BigInt::from(2).pow(L);
        }

        // // hardcoded for testing only
        // let p_str = "228887768202115306593565368808592820237599162302790891136048210859700463168536347859891577256113351052877496083355171100730194866748253815965189419009447097559570228359696848947525043155201021818338978912026318620560515741646245029449014851622920104903693275061770186381936314279545231142191270874232085907767";
        // let q_str = "117856446678054745990472425711910435781072493645370951370838434118297543700237047098408115413013509045457837730951824888879845476417708877498761573788305597382464330724492497557874169226512497782816524324645552982006382507540861532391525971690563763493899740442298815254333451503908665030820892318703151902127";
        // let p = BigInt::from_str_radix(p_str, 10).unwrap();
        // let q = BigInt::from_str_radix(q_str, 10).unwrap();
        // let n = &p * &q;
        // let nn = &n * &n;
        // let ek = EncryptionKey { n, nn };
        // let dk = DecryptionKey { p, q };

        Keys {
            u_i: u,
            y_i: y,
            dk,
            ek,
            party_index: index,
        }
    }

    pub fn create_from(u: (Scalar<Secp256k1>, Scalar<Secp256k1>), index: u16) -> Keys {
        let y = (Point::generator() * &u.0, Point::generator() * &u.1);
        let (ek, dk) = Paillier::keypair().keys();

        Self {
            u_i: u,
            y_i: y,
            dk,
            ek,
            party_index: index,
        }
    }

    pub fn create_from_with_safe_prime(
        u: (Scalar<Secp256k1>, Scalar<Secp256k1>),
        index: u16,
    ) -> Keys {
        let y = (Point::generator() * &u.0, Point::generator() * &u.1);

        let (mut ek, mut dk) = Paillier::keypair_safe_primes().keys();
        let mut bound = ek.n.sqrt() * BigInt::from(2).pow(L);
        while dk.p <= -(&bound) || dk.p >= bound || dk.q <= -(&bound) || dk.q >= bound {
            (ek, dk) = Paillier::keypair_safe_primes().keys();
            bound = ek.n.sqrt() * BigInt::from(2).pow(L);
        }

        // // hardcoded for testing only
        // let p_str = "228887768202115306593565368808592820237599162302790891136048210859700463168536347859891577256113351052877496083355171100730194866748253815965189419009447097559570228359696848947525043155201021818338978912026318620560515741646245029449014851622920104903693275061770186381936314279545231142191270874232085907767";
        // let q_str = "117856446678054745990472425711910435781072493645370951370838434118297543700237047098408115413013509045457837730951824888879845476417708877498761573788305597382464330724492497557874169226512497782816524324645552982006382507540861532391525971690563763493899740442298815254333451503908665030820892318703151902127";
        // let p = BigInt::from_str_radix(p_str, 10).unwrap();
        // let q = BigInt::from_str_radix(q_str, 10).unwrap();
        // let n = &p * &q;
        // let nn = &n * &n;
        // let ek = EncryptionKey { n, nn };
        // let dk = DecryptionKey { p, q };

        Self {
            u_i: u,
            y_i: y,
            dk,
            ek,
            party_index: index,
        }
    }

    pub fn phase1_com_decom(&self) -> (KeyGenBroadcastMessage1, KeyGenDecommitMessage1) {
        let blind_factor = (BigInt::sample(SECURITY), BigInt::sample(SECURITY));
        // let correct_key_proof = NiCorrectKeyProof::proof(&self.dk, None);
        let com = (
            HashCommitment::<Sha256>::create_commitment_with_user_defined_randomness(
                &BigInt::from_bytes(self.y_i.0.to_bytes(true).as_ref()),
                &blind_factor.0,
            ),
            HashCommitment::<Sha256>::create_commitment_with_user_defined_randomness(
                &BigInt::from_bytes(self.y_i.1.to_bytes(true).as_ref()),
                &blind_factor.1,
            ),
        );
        let bcm1 = KeyGenBroadcastMessage1 {
            e: self.ek.clone(),
            com,
            // correct_key_proof,
        };
        let decom1 = KeyGenDecommitMessage1 {
            blind_factor,
            y_i: self.y_i.clone(),
        };
        (bcm1, decom1)
    }

    pub fn phase3_proof_of_correct_key(
        &self,
        nsf_setup: &DLogStatement,
        binding: &BigInt,
    ) -> PaillierKeyProofs {
        let correct_key_proof = NiCorrectKeyProof::proof(&self.dk, None); // TODO: unnecessary?
        let pblum_modulus_proof =
            PaillierBlumModProof::generate(&self.ek.n, &self.dk, binding).unwrap();
        let no_small_factor_proof = NSFProof::generate(&nsf_setup, &self.ek.n, &self.dk, "");

        PaillierKeyProofs {
            correct_key_proof,
            pblum_modulus_proof,
            no_small_factor_proof,
        }
    }

    #[allow(clippy::type_complexity)]
    pub fn phase1_verify_com_phase3_verify_correct_key_phase2_distribute(
        &self,
        params: &(Parameters, Parameters),
        decom_vec: &[KeyGenDecommitMessage1],
        bc1_vec: &[KeyGenBroadcastMessage1],
        pproofs_vec: &[PaillierKeyProofs],
        enc_keys: &[BigInt],
        dlog_statement_vec: &[DLogStatement],
    ) -> Outcome<(
        (VerifiableSS<Secp256k1>, VerifiableSS<Secp256k1>),
        (Vec<Scalar<Secp256k1>>, Vec<Scalar<Secp256k1>>),
        u16,
    )> {
        // test length:
        assert_throw!(decom_vec.len() == usize::from(params.0.share_count));
        assert_throw!(bc1_vec.len() == usize::from(params.0.share_count));
        assert_throw!(pproofs_vec.len() == usize::from(params.0.share_count));
        assert_throw!(enc_keys.len() == usize::from(params.0.share_count));
        // test paillier correct key and test decommitments
        let correct_key_correct_decom_all = (0..bc1_vec.len()).all(|i| {
            (
                HashCommitment::<Sha256>::create_commitment_with_user_defined_randomness(
                    &BigInt::from_bytes(decom_vec[i].y_i.0.to_bytes(true).as_ref()),
                    &decom_vec[i].blind_factor.0,
                ),
                HashCommitment::<Sha256>::create_commitment_with_user_defined_randomness(
                    &BigInt::from_bytes(decom_vec[i].y_i.1.to_bytes(true).as_ref()),
                    &decom_vec[i].blind_factor.1,
                ),
            ) == bc1_vec[i].com
                && pproofs_vec[i]
                    .correct_key_proof
                    .verify(&bc1_vec[i].e, zk_paillier::zkproofs::SALT_STRING)
                    .is_ok()
                && pproofs_vec[i]
                    .pblum_modulus_proof
                    .verify(&bc1_vec[i].e.n, &enc_keys[i])
                && pproofs_vec[i]
                    .no_small_factor_proof
                    .verify(&dlog_statement_vec[i], &bc1_vec[i].e.n)
        });

        let (vss_scheme_inner, secret_shares_inner) =
            VerifiableSS::share(params.0.threshold, params.0.share_count, &self.u_i.0);
        let (vss_scheme_outer, secret_shares_outer) =
            VerifiableSS::share(params.1.threshold, params.1.share_count, &self.u_i.1);
        assert_throw!(correct_key_correct_decom_all);
        Ok((
            (vss_scheme_inner, vss_scheme_outer),
            (secret_shares_inner.to_vec(), secret_shares_outer.to_vec()),
            self.party_index,
        ))
    }

    pub fn phase2_verify_vss_construct_keypair_phase3_pok_dlog(
        &self,
        params: (&Parameters, &Parameters),
        y_vec: (&[Point<Secp256k1>], &[Point<Secp256k1>]),
        secret_shares_vec: (&[Scalar<Secp256k1>], &[Scalar<Secp256k1>]),
        vss_scheme_vec: (&[VerifiableSS<Secp256k1>], &[VerifiableSS<Secp256k1>]),
        index: u16,
    ) -> Outcome<(
        SharedKeys,
        (DLogProof<Secp256k1, Sha256>, DLogProof<Secp256k1, Sha256>),
    )> {
        assert_throw!(y_vec.0.len() == usize::from(params.0.share_count));
        assert_throw!(secret_shares_vec.0.len() == usize::from(params.0.share_count));
        assert_throw!(vss_scheme_vec.0.len() == usize::from(params.0.share_count));
        assert_throw!(y_vec.1.len() == usize::from(params.1.share_count));
        assert_throw!(secret_shares_vec.1.len() == usize::from(params.1.share_count));
        assert_throw!(vss_scheme_vec.1.len() == usize::from(params.1.share_count));

        let correct_ss_verify_inner = (0..y_vec.0.len()).all(|i| {
            vss_scheme_vec.0[i]
                .validate_share(&secret_shares_vec.0[i], index)
                .is_ok()
                && vss_scheme_vec.0[i].commitments[0] == y_vec.0[i]
        });
        let correct_ss_verify_outer = (0..y_vec.1.len()).all(|i| {
            vss_scheme_vec.1[i]
                .validate_share(&secret_shares_vec.1[i], index)
                .is_ok()
                && vss_scheme_vec.1[i].commitments[0] == y_vec.1[i]
        });

        assert_throw!(correct_ss_verify_inner);
        assert_throw!(correct_ss_verify_outer);
        let y: Point<Secp256k1> = y_vec.1.iter().sum(); // anyway, y will be reassigned soon
        let x_i: (Scalar<Secp256k1>, Scalar<Secp256k1>) = (
            secret_shares_vec.0.iter().sum(),
            secret_shares_vec.1.iter().sum(),
        );
        let dlog_proof = (DLogProof::prove(&x_i.0), DLogProof::prove(&x_i.1));
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
        dlog_proofs_vec: &[(DLogProof<Secp256k1, Sha256>, DLogProof<Secp256k1, Sha256>)],
        y_vec: (&[Point<Secp256k1>], &[Point<Secp256k1>]),
    ) -> Outcome<()> {
        assert_throw!(y_vec.0.len() == usize::from(params.share_count)); // or y_vec.1.len()
        assert_throw!(dlog_proofs_vec.len() == usize::from(params.share_count));

        let xi_dlog_verify_inner =
            (0..y_vec.0.len()).all(|i| DLogProof::verify(&dlog_proofs_vec[i].0).is_ok());
        let xi_dlog_verify_outer =
            (0..y_vec.1.len()).all(|i| DLogProof::verify(&dlog_proofs_vec[i].1).is_ok());

        assert_throw!(xi_dlog_verify_inner, "InvalidKey");
        assert_throw!(xi_dlog_verify_outer, "InvalidKey");
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

    pub fn y_i(&self) -> (Point<Secp256k1>, Point<Secp256k1>) {
        (
            Point::generator() * &self.u_i.0,
            Point::generator() * &self.u_i.1,
        )
    }

    pub fn decrypt(&self, ciphertext: BigInt) -> RawPlaintext {
        Paillier::decrypt(&self.dk, &RawCiphertext::from(ciphertext))
    }

    // pub fn refresh_private_key(&self, factor: &Scalar<Secp256k1>, index: u16) -> Keys {
    //     let u: Scalar<Secp256k1> = &self.u_i + factor;
    //     let y = Point::generator() * &u;
    //     let (ek, dk) = Paillier::keypair().keys();

    //     Keys {
    //         u_i: u,
    //         y_i: y,
    //         dk,
    //         ek,
    //         party_index: index,
    //     }
    // }

    // // we recommend using safe primes if the code is used in production
    // pub fn refresh_private_key_safe_prime(&self, factor: &Scalar<Secp256k1>, index: u16) -> Keys {
    //     let u: Scalar<Secp256k1> = &self.u_i + factor;
    //     let y = Point::generator() * &u;
    //     let (ek, dk) = Paillier::keypair_safe_primes().keys();

    //     Keys {
    //         u_i: u,
    //         y_i: y,
    //         dk,
    //         ek,
    //         party_index: index,
    //     }
    // }

    // // used for verifiable recovery
    // pub fn to_encrypted_segment(
    //     &self,
    //     segment_size: usize,
    //     num_of_segments: usize,
    //     pub_ke_y: &Point<Secp256k1>,
    //     g: &Point<Secp256k1>,
    // ) -> (Witness, Helgamalsegmented) {
    //     Msegmentation::to_encrypted_segments(&self.u_i, &segment_size, num_of_segments, pub_ke_y, g)
    // }

    pub fn update_private_key(
        &self,
        factor_u_i: &Scalar<Secp256k1>,
        factor_x_i: &Scalar<Secp256k1>,
    ) -> Self {
        PartyPrivate {
            u_i: (self.u_i.0.clone(), &self.u_i.1 + factor_u_i),
            x_i: (self.x_i.0.clone(), &self.x_i.1 + factor_x_i),
            dk: self.dk.clone(),
        }
    }
}

impl SignKeys {
    pub fn create(
        private: &PartyPrivate,
        vss_scheme: (&VerifiableSS<Secp256k1>, &VerifiableSS<Secp256k1>),
        index: u16,
        s: (&[u16], &[u16]),
    ) -> Self {
        let li_inner = VerifiableSS::<Secp256k1>::map_share_to_new_params(
            &vss_scheme.0.parameters,
            index,
            s.0,
        );
        let li_outer = VerifiableSS::<Secp256k1>::map_share_to_new_params(
            &vss_scheme.1.parameters,
            index,
            s.1,
        );
        let w_i = li_inner * &private.x_i.0 + li_outer * &private.x_i.1;
        let g_w_i = Point::generator() * &w_i;
        let gamma_i = Scalar::<Secp256k1>::random();
        let g_gamma_i = Point::generator() * &gamma_i;

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
        // from the MtAwc, which is handling the proof of knowledge verification of gamma_i such that
        // Gamme_i = gamma_i * G in the verify_proofs_get_alpha()
        let test_b_vec_and_com = (0..b_proof_vec.len()).all(|i| {
            b_proof_vec[i].pk == phase1_decommit_vec[i].g_gamma_i
                && HashCommitment::<Sha256>::create_commitment_with_user_defined_randomness(
                    &BigInt::from_bytes(phase1_decommit_vec[i].g_gamma_i.to_bytes(true).as_ref()),
                    &phase1_decommit_vec[i].blind_factor,
                ) == bc1_vec[i].com
        });

        assert_throw!(test_b_vec_and_com, "InvalidKey");
        let gamma_sum: Point<Secp256k1> = phase1_decommit_vec
            .iter()
            .map(|decom| &decom.g_gamma_i)
            .sum();
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
        decom_vec: &[Phase5ADecom1],
        com_vec: &[Phase5Com1],
        elgamal_proofs: &[HomoELGamalProof<Secp256k1, Sha256>],
        dlog_proofs_rho: &[DLogProof<Secp256k1, Sha256>],
        v_i: &Point<Secp256k1>,
        R: &Point<Secp256k1>,
    ) -> Outcome<(Phase5Com2, Phase5DDecom2)> {
        assert_eq!(decom_vec.len(), com_vec.len());

        let g = Point::generator();
        let test_com_elgamal = (0..com_vec.len()).all(|i| {
            let delta = HomoElGamalStatement {
                G: decom_vec[i].A_i.clone(),
                H: R.clone(),
                Y: g.to_point(),
                D: decom_vec[i].V_i.clone(),
                E: decom_vec[i].B_i.clone(),
            };

            let input_hash = Sha256::new()
                .chain_points([&decom_vec[i].V_i, &decom_vec[i].A_i, &decom_vec[i].B_i])
                .result_bigint();

            HashCommitment::<Sha256>::create_commitment_with_user_defined_randomness(
                &input_hash,
                &decom_vec[i].blind_factor,
            ) == com_vec[i].com
                && elgamal_proofs[i].verify(&delta).is_ok()
                && DLogProof::verify(&dlog_proofs_rho[i]).is_ok()
        });

        let v_iter = (0..com_vec.len()).map(|i| &decom_vec[i].V_i);
        let a_iter = (0..com_vec.len()).map(|i| &decom_vec[i].A_i);

        let v = v_i + v_iter.sum::<Point<Secp256k1>>();
        // V = -mG -ry - sum (vi)
        let a: Point<Secp256k1> = a_iter.sum();

        let r = Scalar::<Secp256k1>::from(
            &self
                .R
                .x_coord()
                .ifnone("InvalidSig", "")?
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

        assert_throw!(test_com_elgamal, "InvalidCom");

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

        let test_com = (0..com_vec2.len()).all(|i| {
            let input_hash = Sha256::new()
                .chain_points([&decom_vec2[i].u_i, &decom_vec2[i].t_i])
                .result_bigint();
            HashCommitment::<Sha256>::create_commitment_with_user_defined_randomness(
                &input_hash,
                &decom_vec2[i].blind_factor,
            ) == com_vec2[i].com
        });

        let t_iter = decom_vec2.iter().map(|decom| &decom.t_i);
        let u_iter = decom_vec2.iter().map(|decom| &decom.u_i);
        let b_iter = decom_vec1.iter().map(|decom| &decom.B_i);

        let g = Point::generator();
        let biased_sum_tb = g + t_iter.chain(b_iter).sum::<Point<Secp256k1>>();
        let biased_sum_tb_minus_u = biased_sum_tb - u_iter.sum::<Point<Secp256k1>>();
        assert_throw!(test_com, "InvalidCom");
        assert_throw!(*g.as_point() == biased_sum_tb_minus_u, "InvalidKey");
        Ok(self.s_i.clone())
    }

    pub fn output_signature(&self, s_vec: &[Scalar<Secp256k1>]) -> Outcome<SignatureRecid> {
        let mut s = &self.s_i + s_vec.iter().sum::<Scalar<Secp256k1>>();
        let s_bn = s.to_bigint();

        let r = Scalar::<Secp256k1>::from(
            &self
                .R
                .x_coord()
                .ifnone("InvalidSig", "")?
                .mod_floor(Scalar::<Secp256k1>::group_order()),
        );
        let ry: BigInt = self
            .R
            .y_coord()
            .ifnone("InvalidSig", "")?
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
        let std_verified = std_verify(&sig, &self.y, &self.m).is_ok();
        assert_throw!(std_verified, "InvalidSig");
        Ok(sig)
    }
}

// pub fn std_verify(
//     sig: &SignatureRecid,
//     y: &Point<Secp256k1>,
//     message: &BigInt,
// ) -> Result<(), Error> {
//     let b = sig.s.invert().ok_or(Error::InvalidSig)?;
//     let a = Scalar::<Secp256k1>::from(message);
//     let u1 = a * &b;
//     let u2 = &sig.r * &b;

//     let g = Point::generator();
//     let gu1 = g * u1;
//     let yu2 = y * &u2;
//     // can be faster using shamir trick

//     if sig.r
//         == Scalar::<Secp256k1>::from(
//             &(gu1 + yu2)
//                 .x_coord()
//                 .ok_or(Error::InvalidSig)?
//                 .mod_floor(Scalar::<Secp256k1>::group_order()),
//         )
//     {
//         Ok(())
//     } else {
//         Err(InvalidSig)
//     }
// }

pub fn std_verify(sig: &SignatureRecid, pk: &Point<Secp256k1>, msg: &BigInt) -> Outcome<()> {
    // input parameter msg is a hashed value of the raw message to be signed
    let s_inv: Scalar<Secp256k1> = sig
        .s
        .invert()
        .unwrap_or_else(|| Scalar::<Secp256k1>::zero());
    let r_prime = (&s_inv * &Scalar::<Secp256k1>::from_bigint(&msg)) * Point::generator()
        + (&sig.r * &s_inv) * pk;
    if r_prime.x_coord().unwrap_or_else(|| BigInt::from(0u16)) == sig.r.to_bigint() {
        Ok(())
    } else {
        throw!("InvalidSig", "");
    }
}
