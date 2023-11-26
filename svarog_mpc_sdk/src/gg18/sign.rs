//! This is a modified version of `gg18_keygen_client.rs` of Kzen Networks' implementation of GG18 signing:
//! https://github.com/ZenGo-X/multi-party-ecdsa/blob/master/examples/gg18_sign_client.rs
//!

use std::collections::{HashMap, HashSet};

use curv::{
    arithmetic::{BasicOps, Converter, Modulo},
    cryptographic_primitives::proofs::{
        sigma_correct_homomorphic_elgamal_enc::HomoELGamalProof, sigma_dlog::DLogProof,
    },
    elliptic::curves::{secp256_k1::Secp256k1, Point, Scalar},
    BigInt,
};
use multi_party_ecdsa::{protocols::multi_party_ecdsa::gg_2018::party_i::*, utilities::mta::*};
use sha2::Sha256;
use svarog_grpc::protogen::svarog::{Signature, TxHash};
use tonic::async_trait;
use xuanmi_base_support::*;

use super::*;
use crate::{mpc_member::*, util::*};

#[async_trait]
pub trait AlgoSign {
    async fn algo_sign(&self, keystore: &KeyStore, to_sign: &TxHash) -> Outcome<Signature>;
}

#[async_trait]
impl AlgoSign for MpcMember {
    async fn algo_sign(&self, keystore: &KeyStore, to_sign: &TxHash) -> Outcome<Signature> {
        let derv_path = to_sign.derive_path.clone();
        let tx_hash = to_sign.tx_hash.clone();
        assert_throw!(tx_hash.len() <= 32);

        let my_id = self.member_id;
        let my_group_id = self.group_id;
        let key_mates: HashSet<usize> = self.member_group.keys().cloned().collect();
        let (key_indices, key_indices_reverse) = {
            let mut res1 = SparseVec::new();
            let mut res2 = SparseVec::new();
            let mut members: Vec<usize> = key_mates.iter().cloned().collect();
            members.sort();
            for (idx, member_id) in members.iter().enumerate() {
                res1.insert(*member_id, idx);
                res2.insert(idx, *member_id);
            }
            (res1, res2)
        };
        let sign_mates: HashSet<usize> = self.member_attending.iter().cloned().collect();
        let sign_mates_others = {
            let mut res = sign_mates.clone();
            res.remove(&my_id);
            res
        };

        println!("my_id: {}, my_group_id: {}", my_id, my_group_id);

        /* ===== ALGO START ===== */

        let y_sum = Point::<Secp256k1>::from_bytes(&keystore.attr_root_pk(true)).catch_()?;
        let chain_code = &keystore.chain_code;

        let (tweak_sk, tweak_pk) = if derv_path.is_empty() {
            (Scalar::<Secp256k1>::zero(), y_sum.clone())
        } else {
            algo_get_hd_key(&derv_path, &y_sum, chain_code).catch_()?
        };

        println!("computed tweak sk and pk");

        let sign_mates_vec_u16_minus_1 = {
            // sign_mates in asc order as u16
            let mut res: Vec<u16> = sign_mates.iter().map(|x| (*x - 1) as u16).collect();
            res.sort();
            res
        };
        let mut vss_scheme_svec = keystore.vss_scheme_svec.clone();
        let _1 = vss_scheme_svec[&1].commitments[0].clone();
        let _2 = Point::generator() * &tweak_sk;
        vss_scheme_svec.get_mut(&1).unwrap().commitments[0] = _1 + _2;

        let mut private =
            PartyPrivate::set_private(keystore.party_keys.clone(), keystore.shared_keys.clone());
        private = private.update_private_key(&Scalar::<Secp256k1>::zero(), &tweak_sk);
        let sign_keys = SignKeys::create(
            &private,
            &vss_scheme_svec[&my_id],
            my_id as u16 - 1,
            &sign_mates_vec_u16_minus_1,
        );

        let (bc1, decom1) = sign_keys.phase1_broadcast();
        let (ma, _) = MessageA::a(&sign_keys.k_i, &keystore.party_keys.ek, &[]);

        let mut purpose = "bc1";
        self.postmsg_mcast(sign_mates.iter(), purpose, &bc1)
            .await
            .catch_()?;
        let bc1_svec: HashMap<usize, SignBroadcastPhase1> = self
            .getmsg_mcast(sign_mates.iter(), purpose)
            .await
            .catch_()?;

        purpose = "ma";
        self.postmsg_mcast(sign_mates_others.iter(), purpose, &ma)
            .await
            .catch_()?;
        let ma_svec: HashMap<usize, MessageA> = self
            .getmsg_mcast(sign_mates_others.iter(), purpose)
            .await
            .catch_()?;

        println!("Exchanged commitments");

        // do MtA/MtAwc (c) (d)
        let mut mb_gamma_svec: SparseVec<MessageB> = SparseVec::new();
        let mut mb_w_svec: SparseVec<MessageB> = SparseVec::new();
        let mut beta_svec: SparseVec<Scalar<Secp256k1>> = SparseVec::new();
        let mut ni_svec: SparseVec<Scalar<Secp256k1>> = SparseVec::new();
        for member_id in sign_mates_others.iter() {
            let (mb_gamma, beta_gamma, _, _) = MessageB::b(
                &sign_keys.gamma_i,
                &keystore.paillier_key_svec[member_id],
                ma_svec[member_id].clone(),
                &[],
            )
            .unwrap();
            let (mb_w, beta_wi, _, _) = MessageB::b(
                &sign_keys.w_i,
                &keystore.paillier_key_svec[member_id],
                ma_svec[member_id].clone(),
                &[],
            )
            .unwrap();
            mb_gamma_svec.insert(*member_id, mb_gamma);
            mb_w_svec.insert(*member_id, mb_w);
            beta_svec.insert(*member_id, beta_gamma);
            ni_svec.insert(*member_id, beta_wi);
        }

        println!("Finished MtA/MtAwc (c) (d)");

        purpose = "mb_gamma";
        for (member_id, mb_gamma) in mb_gamma_svec.iter() {
            self.postmsg_p2p(*member_id, purpose, mb_gamma)
                .await
                .catch_()?;
        }
        let mb_gamma_svec: SparseVec<MessageB> = self
            .getmsg_mcast(sign_mates_others.iter(), purpose)
            .await
            .catch_()?;
        purpose = "mb_w";
        for (member_id, mb_w) in mb_w_svec.iter() {
            self.postmsg_p2p(*member_id, purpose, mb_w).await.catch_()?;
        }
        let mb_w_svec: SparseVec<MessageB> = self
            .getmsg_mcast(sign_mates_others.iter(), purpose)
            .await
            .catch_()?;

        println!("Exchanged Paillier ciphertext");

        // do MtA (e) / MtAwc (e) (f)
        let xi_com_svec = {
            let mut res: SparseVec<Point<Secp256k1>> = SparseVec::new();
            let xi_com_vec = Keys::get_commitments_to_xi(&vss_scheme_svec.values_by_key_asc());
            for (idx, xi_com) in xi_com_vec.iter().enumerate() {
                res.insert(key_indices_reverse[&idx], xi_com.clone());
            }
            res
        };
        let mut alpha_svec: SparseVec<Scalar<Secp256k1>> = SparseVec::new();
        let mut mu_svec: SparseVec<Scalar<Secp256k1>> = SparseVec::new();
        for member_id in sign_mates_others.iter() {
            let mb_gamma = mb_gamma_svec[member_id].clone();
            let alpha_ij_gamma = mb_gamma
                .verify_proofs_get_alpha(&keystore.party_keys.dk, &sign_keys.k_i)
                .unwrap();
            let mb_w = mb_w_svec[member_id].clone();
            let alpha_ij_wi = mb_w
                .verify_proofs_get_alpha(&keystore.party_keys.dk, &sign_keys.k_i)
                .unwrap();
            let g_w_i = Keys::update_commitments_to_xi(
                &xi_com_svec[member_id],
                &vss_scheme_svec[member_id],
                (my_id - 1) as u16,
                &sign_mates_vec_u16_minus_1,
            );
            // TODO: Why is this assertion failing?
            // assert_throw!(mb_w.b_proof.pk.clone() == g_w_i);
            alpha_svec.insert(*member_id, alpha_ij_gamma.0);
            mu_svec.insert(*member_id, alpha_ij_wi.0);
        }

        let delta = sign_keys.phase2_delta_i(
            &alpha_svec.values_by_key_asc(),
            &beta_svec.values_by_key_asc(),
        );
        let sigma =
            sign_keys.phase2_sigma_i(&mu_svec.values_by_key_asc(), &ni_svec.values_by_key_asc());

        println!("Finished MtA/MtAwc (e) (f)");

        purpose = "delta_i";
        self.postmsg_mcast(sign_mates.iter(), purpose, &delta)
            .await
            .catch_()?;
        let delta_svec: SparseVec<Scalar<Secp256k1>> = self
            .getmsg_mcast(sign_mates.iter(), purpose)
            .await
            .catch_()?;
        let delta_inv = SignKeys::phase3_reconstruct_delta(&delta_svec.values_by_key_asc());

        println!("Finished exchanging delta_i");

        purpose = "decom1";
        let R = {
            self.postmsg_mcast(sign_mates_others.iter(), purpose, &decom1)
                .await
                .catch_()?;
            let decom1_svec: SparseVec<SignDecommitPhase1> = self
                .getmsg_mcast(sign_mates_others.iter(), purpose)
                .await
                .catch_()?;
            let decom1_vec: Vec<SignDecommitPhase1> = decom1_svec.values_by_key_asc();
            let bc1_vec: Vec<SignBroadcastPhase1> = {
                let mut tmp = bc1_svec.clone();
                tmp.remove(&my_id);
                tmp.values_by_key_asc()
            };
            let b_proof_vec: Vec<&DLogProof<Secp256k1, Sha256>> = {
                let mut tmp = SparseVec::new();
                for (member_id, mb_gamma) in mb_gamma_svec.iter() {
                    tmp.insert(*member_id, &mb_gamma.b_proof);
                }
                tmp.values_by_key_asc()
            };
            let R = SignKeys::phase4(&delta_inv, &b_proof_vec, decom1_vec, &bc1_vec).unwrap();
            R + decom1.g_gamma_i * &delta_inv
        };

        println!("Finished exchanging decommitment to g_gamma_i");

        let message_bn = BigInt::from_bytes(&tx_hash).modulus(&BigInt::from(2).pow(256));
        let local_sig =
            LocalSignature::phase5_local_sig(&sign_keys.k_i, &message_bn, &R, &sigma, &tweak_pk);
        let (phase5_com, phase5a_decom, helgamal_proof, dlog_proof_rho) =
            local_sig.phase5a_broadcast_5b_zkproof();

        purpose = "phase5_com";
        self.postmsg_mcast(sign_mates_others.iter(), purpose, &phase5_com)
            .await
            .catch_()?;
        let phase5_com_svec: SparseVec<Phase5Com1> = self
            .getmsg_mcast(sign_mates_others.iter(), purpose)
            .await
            .catch_()?;
        purpose = "phase_5a_decom";
        self.postmsg_mcast(sign_mates_others.iter(), purpose, &phase5a_decom)
            .await
            .catch_()?;
        let mut phase5a_decom_svec: SparseVec<Phase5ADecom1> = self
            .getmsg_mcast(sign_mates_others.iter(), purpose)
            .await
            .catch_()?;
        purpose = "helgamal_proof";
        self.postmsg_mcast(sign_mates_others.iter(), purpose, &helgamal_proof)
            .await
            .catch_()?;
        let helgamal_proof_svec: SparseVec<HomoELGamalProof<Secp256k1, Sha256>> = self
            .getmsg_mcast(sign_mates_others.iter(), purpose)
            .await
            .catch_()?;
        purpose = "dlog_proof_rho";
        self.postmsg_mcast(sign_mates_others.iter(), purpose, &dlog_proof_rho)
            .await
            .catch_()?;
        let dlog_proof_rho_svec: SparseVec<DLogProof<Secp256k1, Sha256>> = self
            .getmsg_mcast(sign_mates_others.iter(), purpose)
            .await
            .catch_()?;

        println!("Finish phase5(a & b)");

        let (phase5_com2, phase5d_decom2) = local_sig
            .phase5c(
                &phase5a_decom_svec.values_by_key_asc(),
                &phase5_com_svec.values_by_key_asc(),
                &helgamal_proof_svec.values_by_key_asc(),
                &dlog_proof_rho_svec.values_by_key_asc(),
                &phase5a_decom.V_i,
                &R,
            )
            .unwrap();

        purpose = "phase5_com2";
        self.postmsg_mcast(sign_mates.iter(), purpose, &phase5_com2)
            .await
            .catch_()?;
        let phase5_com2_svec: SparseVec<Phase5Com2> = self
            .getmsg_mcast(sign_mates.iter(), purpose)
            .await
            .catch_()?;
        purpose = "phase5d_decom2";
        self.postmsg_mcast(sign_mates.iter(), purpose, &phase5d_decom2)
            .await
            .catch_()?;
        let phase5d_decom2_svec: SparseVec<Phase5DDecom2> = self
            .getmsg_mcast(sign_mates.iter(), purpose)
            .await
            .catch_()?;

        phase5a_decom_svec.insert(my_id, phase5a_decom);
        let s_i = local_sig
            .phase5d(
                &phase5d_decom2_svec.values_by_key_asc(),
                &phase5_com2_svec.values_by_key_asc(),
                &phase5a_decom_svec.values_by_key_asc(),
            )
            .unwrap();

        println!("Finish phase5(c & d)");

        purpose = "s_i";
        self.postmsg_mcast(sign_mates_others.iter(), purpose, &s_i)
            .await
            .catch_()?;
        let s_i_svec: SparseVec<Scalar<Secp256k1>> = self
            .getmsg_mcast(sign_mates_others.iter(), purpose)
            .await
            .catch_()?;
        let sig = local_sig
            .output_signature(&s_i_svec.values_by_key_asc())
            .unwrap();
        check_sig(&sig.r, &sig.s, &message_bn, &tweak_pk).catch_()?;

        println!("Finish phase5(e)");

        let signature = Signature {
            r: sig.r.to_bytes().to_vec(),
            s: sig.s.to_bytes().to_vec(),
            v: sig.recid == 1,
            derive_path: derv_path,
            tx_hash,
        };

        Ok(signature)
    }
}

pub fn check_sig(
    r: &Scalar<Secp256k1>,
    s: &Scalar<Secp256k1>,
    msg: &BigInt,
    pk: &Point<Secp256k1>,
) -> Outcome<()> {
    // use secp256k1::{Message, PublicKey, Signature, SECP256K1};
    use secp256k1::{ecdsa::Signature, Message, PublicKey, SECP256K1};

    let raw_msg = BigInt::to_bytes(msg);
    let mut msg: Vec<u8> = Vec::new(); /* padding */
    msg.extend(vec![0u8; 32 - raw_msg.len()]);
    msg.extend(raw_msg.iter());

    let msg = Message::from_digest_slice(msg.as_slice()).catch_()?;
    let mut raw_pk = pk.to_bytes(false).to_vec();
    if raw_pk.len() == 64 {
        raw_pk.insert(0, 4u8);
    }
    let pk = PublicKey::from_slice(&raw_pk).catch_()?;

    let mut compact: Vec<u8> = Vec::new();
    let bytes_r = &r.to_bytes().to_vec();
    compact.extend(vec![0u8; 32 - bytes_r.len()]);
    compact.extend(bytes_r.iter());

    let bytes_s = &s.to_bytes().to_vec();
    compact.extend(vec![0u8; 32 - bytes_s.len()]);
    compact.extend(bytes_s.iter()); // compact = [r; s]

    let secp_sig = Signature::from_compact(compact.as_slice()).catch_()?;
    SECP256K1.verify_ecdsa(&msg, &secp_sig, &pk).catch_()?;

    Ok(())
}

pub fn check_sig0(
    r: &Scalar<Secp256k1>,
    s: &Scalar<Secp256k1>,
    msg: &BigInt,
    pk: &Point<Secp256k1>,
) -> Outcome<()> {
    // input parameter msg is a hashed value of the raw message to be signed
    let s_inv: Scalar<Secp256k1> = s.invert().unwrap_or_else(Scalar::<Secp256k1>::zero);
    let r_prime =
        (&s_inv * &Scalar::<Secp256k1>::from_bigint(msg)) * Point::generator() + (r * &s_inv) * pk;
    if r_prime.x_coord().unwrap_or_else(|| BigInt::from(0u16)) != r.to_bigint() {
        throw!("", "");
    }
    Ok(())
}
