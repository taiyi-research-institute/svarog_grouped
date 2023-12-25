//! This is a modified version of `gg18_keygen_client.rs` of Kzen Networks' implementation of GG18 signing:
//! https://github.com/ZenGo-X/multi-party-ecdsa/blob/master/examples/gg18_sign_client.rs
//!

use std::collections::{HashMap, HashSet};

use super::*;
use crate::{
    assert_throw,
    gg18::{mta::*, multi_party_ecdsa::*},
    mpc_member::*, throw,
};
use curv::{
    arithmetic::{BasicOps, Converter, Modulo},
    cryptographic_primitives::proofs::{
        sigma_correct_homomorphic_elgamal_enc::HomoELGamalProof, sigma_dlog::DLogProof,
    },
    elliptic::curves::{secp256_k1::Secp256k1, Point, Scalar},
    BigInt,
};
use sha2::Sha256;
use svarog_grpc::protogen::svarog::{Signature, TxHash};
use tonic::async_trait;

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
        let sign_mates: HashSet<u16> = self.member_attending.iter().cloned().collect();
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

        let mut vss_scheme_kv = keystore.vss_scheme_kv.clone();
        let _1 = vss_scheme_kv[&1].commitments[0].clone();
        let _2 = Point::generator() * &tweak_sk;
        vss_scheme_kv.get_mut(&1).unwrap().commitments[0] = _1 + _2;

        let mut private =
            PartyPrivate::set_private(keystore.party_keys.clone(), keystore.shared_keys.clone());
        private = private.update_private_key(&Scalar::<Secp256k1>::zero(), &tweak_sk);
        let sign_keys = SignKeys::create(&private, my_id, &sign_mates).catch_()?;

        let (bc1, decom1) = sign_keys.phase1_broadcast();
        let (ma, _) = MessageA::a(&sign_keys.k_i, &keystore.party_keys.ek, &HashMap::new());

        let mut purpose = "bc1";
        self.postmsg_mcast(sign_mates.iter(), purpose, &bc1)
            .await
            .catch_()?;
        let bc1_kv: HashMap<u16, SignBroadcastPhase1> = self
            .getmsg_mcast(sign_mates.iter(), purpose)
            .await
            .catch_()?;

        purpose = "ma";
        self.postmsg_mcast(sign_mates_others.iter(), purpose, &ma)
            .await
            .catch_()?;
        let ma_kv: HashMap<u16, MessageA> = self
            .getmsg_mcast(sign_mates_others.iter(), purpose)
            .await
            .catch_()?;

        println!("Exchanged commitments");

        // do MtA/MtAwc (c) (d)
        let mut mb_gamma_kv: HashMap<u16, MessageB> = HashMap::new();
        let mut mb_w_kv: HashMap<u16, MessageB> = HashMap::new();
        let mut beta_kv: HashMap<u16, Scalar<Secp256k1>> = HashMap::new();
        let mut ni_kv: HashMap<u16, Scalar<Secp256k1>> = HashMap::new();
        for member_id in sign_mates_others.iter() {
            let (mb_gamma, beta_gamma, _, _) = MessageB::b(
                &sign_keys.gamma_i,
                &keystore.paillier_key_kv[member_id],
                ma_kv[member_id].clone(),
                &HashMap::new(),
            )
            .unwrap();
            let (mb_w, beta_wi, _, _) = MessageB::b(
                &sign_keys.w_i,
                &keystore.paillier_key_kv[member_id],
                ma_kv[member_id].clone(),
                &HashMap::new(),
            )
            .unwrap();
            mb_gamma_kv.insert(*member_id, mb_gamma);
            mb_w_kv.insert(*member_id, mb_w);
            beta_kv.insert(*member_id, beta_gamma);
            ni_kv.insert(*member_id, beta_wi);
        }

        println!("Finished MtA/MtAwc (c) (d)");

        purpose = "mb_gamma";
        for (member_id, mb_gamma) in mb_gamma_kv.iter() {
            self.postmsg_p2p(*member_id, purpose, mb_gamma)
                .await
                .catch_()?;
        }
        let mb_gamma_kv: HashMap<u16, MessageB> = self
            .getmsg_mcast(sign_mates_others.iter(), purpose)
            .await
            .catch_()?;
        purpose = "mb_w";
        for (member_id, mb_w) in mb_w_kv.iter() {
            self.postmsg_p2p(*member_id, purpose, mb_w).await.catch_()?;
        }
        let mb_w_kv: HashMap<u16, MessageB> = self
            .getmsg_mcast(sign_mates_others.iter(), purpose)
            .await
            .catch_()?;

        println!("Exchanged Paillier ciphertext");

        // do MtA (e) / MtAwc (e) (f)
        let xi_com_kv: HashMap<u16, Point<Secp256k1>> =
            Keys::get_commitments_to_xi(&vss_scheme_kv).catch_()?;
        let mut alpha_kv: HashMap<u16, Scalar<Secp256k1>> = HashMap::new();
        let mut mu_kv: HashMap<u16, Scalar<Secp256k1>> = HashMap::new();
        for member_id in sign_mates_others.iter() {
            let mb_gamma = mb_gamma_kv[member_id].clone();
            let alpha_ij_gamma = mb_gamma
                .verify_proofs_get_alpha(&keystore.party_keys.dk, &sign_keys.k_i)
                .unwrap();
            let mb_w = mb_w_kv[member_id].clone();
            let alpha_ij_wi = mb_w
                .verify_proofs_get_alpha(&keystore.party_keys.dk, &sign_keys.k_i)
                .unwrap();
            let g_w_i =
                Keys::update_commitments_to_xi(*member_id, &xi_com_kv[member_id], &sign_mates)
                    .catch_()?;
            assert_throw!(mb_w.b_proof.pk.clone() == g_w_i);
            alpha_kv.insert(*member_id, alpha_ij_gamma.0);
            mu_kv.insert(*member_id, alpha_ij_wi.0);
        }

        let delta = sign_keys.phase2_delta_i(&alpha_kv, &beta_kv).catch_()?;
        let sigma = sign_keys.phase2_sigma_i(&mu_kv, &ni_kv).catch_()?;

        println!("Finished MtA/MtAwc (e) (f)");

        purpose = "delta_i";
        self.postmsg_mcast(sign_mates.iter(), purpose, &delta)
            .await
            .catch_()?;
        let delta_kv: HashMap<u16, Scalar<Secp256k1>> = self
            .getmsg_mcast(sign_mates.iter(), purpose)
            .await
            .catch_()?;
        let delta_inv = SignKeys::phase3_reconstruct_delta(&delta_kv).catch_()?;

        println!("Finished exchanging delta_i");

        purpose = "decom1";
        let R = {
            self.postmsg_mcast(sign_mates_others.iter(), purpose, &decom1)
                .await
                .catch_()?;
            let decom1_kv: HashMap<u16, SignDecommitPhase1> = self
                .getmsg_mcast(sign_mates_others.iter(), purpose)
                .await
                .catch_()?;
            let bc1_kv: HashMap<u16, SignBroadcastPhase1> = {
                let mut tmp = bc1_kv.clone();
                tmp.remove(&my_id);
                tmp
            };
            let b_proof_kv: HashMap<u16, &DLogProof<Secp256k1, Sha256>> = {
                let mut tmp = HashMap::new();
                for (member_id, mb_gamma) in mb_gamma_kv.iter() {
                    tmp.insert(*member_id, &mb_gamma.b_proof);
                }
                tmp
            };
            let R = SignKeys::phase4(&delta_inv, &b_proof_kv, &decom1_kv, &bc1_kv).unwrap();
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
        let phase5_com_kv: HashMap<u16, Phase5Com1> = self
            .getmsg_mcast(sign_mates_others.iter(), purpose)
            .await
            .catch_()?;
        purpose = "phase_5a_decom";
        self.postmsg_mcast(sign_mates_others.iter(), purpose, &phase5a_decom)
            .await
            .catch_()?;
        let mut phase5a_decom_kv: HashMap<u16, Phase5ADecom1> = self
            .getmsg_mcast(sign_mates_others.iter(), purpose)
            .await
            .catch_()?;
        purpose = "helgamal_proof";
        self.postmsg_mcast(sign_mates_others.iter(), purpose, &helgamal_proof)
            .await
            .catch_()?;
        let helgamal_proof_kv: HashMap<u16, HomoELGamalProof<Secp256k1, Sha256>> = self
            .getmsg_mcast(sign_mates_others.iter(), purpose)
            .await
            .catch_()?;
        purpose = "dlog_proof_rho";
        self.postmsg_mcast(sign_mates_others.iter(), purpose, &dlog_proof_rho)
            .await
            .catch_()?;
        let dlog_proof_rho_kv: HashMap<u16, DLogProof<Secp256k1, Sha256>> = self
            .getmsg_mcast(sign_mates_others.iter(), purpose)
            .await
            .catch_()?;

        println!("Finish phase5(a & b)");

        let (phase5_com2, phase5d_decom2) = local_sig
            .phase5c(
                &phase5a_decom_kv,
                &phase5_com_kv,
                &helgamal_proof_kv,
                &dlog_proof_rho_kv,
                &phase5a_decom.V_i,
                &R,
            )
            .unwrap();

        purpose = "phase5_com2";
        self.postmsg_mcast(sign_mates.iter(), purpose, &phase5_com2)
            .await
            .catch_()?;
        let phase5_com2_kv: HashMap<u16, Phase5Com2> = self
            .getmsg_mcast(sign_mates.iter(), purpose)
            .await
            .catch_()?;
        purpose = "phase5d_decom2";
        self.postmsg_mcast(sign_mates.iter(), purpose, &phase5d_decom2)
            .await
            .catch_()?;
        let phase5d_decom2_kv: HashMap<u16, Phase5DDecom2> = self
            .getmsg_mcast(sign_mates.iter(), purpose)
            .await
            .catch_()?;

        phase5a_decom_kv.insert(my_id, phase5a_decom);
        let s_i = local_sig
            .phase5d(&phase5d_decom2_kv, &phase5_com2_kv, &phase5a_decom_kv)
            .unwrap();

        println!("Finish phase5(c & d)");

        purpose = "s_i";
        self.postmsg_mcast(sign_mates_others.iter(), purpose, &s_i)
            .await
            .catch_()?;
        let s_i_kv: HashMap<u16, Scalar<Secp256k1>> = self
            .getmsg_mcast(sign_mates_others.iter(), purpose)
            .await
            .catch_()?;
        let sig = local_sig.output_signature(&s_i_kv).unwrap();
        check_sig(&sig.r, &sig.s, &message_bn, &tweak_pk).catch_()?;
        check_sig0(&sig.r, &sig.s, &message_bn, &tweak_pk).catch_()?;

        println!("Finish phase5(e)");

        let signature = Signature {
            r: sig.r.to_bytes().to_vec(),
            s: sig.s.to_bytes().to_vec(),
            v: sig.recid as u32,
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
