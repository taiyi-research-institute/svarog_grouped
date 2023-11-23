//! This is a modified version of `gg18_keygen_client.rs` of Kzen Networks' implementation of GG18 signing:
//! https://github.com/ZenGo-X/multi-party-ecdsa/blob/master/examples/gg18_sign_client.rs
//!

use curv::{
    arithmetic::{BasicOps, Converter, Modulo},
    cryptographic_primitives::{
        proofs::{sigma_correct_homomorphic_elgamal_enc::HomoELGamalProof, sigma_dlog::DLogProof},
        secret_sharing::feldman_vss::VerifiableSS,
    },
    elliptic::curves::{secp256_k1::Secp256k1, Point, Scalar},
    BigInt,
};
use sha2::Sha256;
use svarog_grpc::protogen::svarog::{Signature, TxHash};
use tonic::async_trait;
use xuanmi_base_support::*;

use super::*;
use crate::{
    mta::{MessageA, MessageB},
    util::*,
    MpcMember, MpcPeer,
};

#[async_trait]
pub trait AlgoSign {
    async fn algo_sign(&self, keystore: &KeyStore, to_sign: &[TxHash]) -> Outcome<Vec<Signature>>;
}

#[async_trait]
impl AlgoSign for MpcMember {
    async fn algo_sign(&self, keystore: &KeyStore, to_sign: &[TxHash]) -> Outcome<Vec<Signature>> {
        let NB = to_sign.len();
        let my_id = self.member_id.clone();
        let my_group_id = self.group_id.clone();
        let mut groupmates: Vec<usize> = Vec::new();
        let mut signmates: Vec<usize> = Vec::new();
        for member_id in self.group_member.get(&self.group_id).unwrap() {
            if self.reshare_members.get(member_id).is_none() {
                if self.member_attending.contains(member_id) {
                    groupmates.push(*member_id);
                }
            }
        }
        for (member_id, _) in &self.member_group {
            if self.reshare_members.get(member_id).is_none() {
                if self.member_attending.contains(member_id) {
                    groupmates.push(*member_id);
                }
            }
        }
        groupmates.sort();
        signmates.sort();
        let mut idx_group = 0;
        let mut idx_sign = 0;
        for (idx, member_id) in groupmates.iter().enumerate() {
            if *member_id == self.member_id {
                idx_group = idx;
            }
        }
        for (idx, member_id) in signmates.iter().enumerate() {
            if *member_id == self.member_id {
                idx_sign = idx;
            }
        }
        let NG = group_mates.len();
        let NS = sign_mates.len();
        let mut signatures = Vec::with_capacity(NB);
        let tx_hash_batch: Vec<Vec<u8>> = to_sign
            .iter()
            .map(|tx_hash| tx_hash.tx_hash.clone())
            .collect();
        let derv_path_batch: Vec<String> = to_sign
            .iter()
            .map(|tx_hash| tx_hash.derive_path.clone())
            .collect();
        let chain_code: [u8; 32] = keystore.chain_code.clone();
        let y_sum: Point<Secp256k1> = Point::from_bytes(&keystore.attr_root_pk(true)).catch_()?;

        let (tweak_sk_batch, derv_pk_batch) = {
            let mut tweak_sk_batch = Vec::with_capacity(NB);
            let mut derv_pk_batch = Vec::with_capacity(NB);
            for derive in &derv_path_batch {
                if derive.is_empty() {
                    tweak_sk_batch.push(Scalar::<Secp256k1>::zero());
                    derv_pk_batch.push(y_sum.clone());
                } else {
                    let (tweak_sk, derv_pk) =
                        algo_get_hd_key(derive, &y_sum, &chain_code).catch_()?;
                    tweak_sk_batch.push(tweak_sk);
                    derv_pk_batch.push(derv_pk);
                }
            }
            (tweak_sk_batch, derv_pk_batch)
        };

        let vss_outer_vec = keystore.vss_outer_vec.clone();
        let vss_inner_vec = keystore.vss_inner_vec.clone();

        let mut vss_outer_tweak_batch = Vec::with_capacity(NB);
        for tweak_sk in tweak_sk_batch.iter() {
            let mut vss_outer = keystore.vss_outer_vec[&my_id].clone();
            vss_outer.commitments[0] =
                vss_outer.commitments[0].clone() + Point::generator() * tweak_sk;
            vss_outer_tweak_batch.push(vss_outer);
        }

        let mut sign_keys_batch = Vec::with_capacity(NB);
        let _group_mates_u16 = group_mates.iter().map(|id| *id as u16).collect::<Vec<_>>();
        let _sign_mates_u16 = sign_mates.iter().map(|id| *id as u16).collect::<Vec<_>>();
        for (seqno, _) in vss_outer_tweak_batch.iter().enumerate() {
            let mut private = PartyPrivate::set_private(
                keystore.party_keys.clone(),
                keystore.shared_keys.clone(),
            );
            private =
                private.update_private_key(&Scalar::<Secp256k1>::zero(), &tweak_sk_batch[seqno]);
            let inner_outer = (&vss_inner_vec[&my_id], &vss_outer_tweak_batch[seqno]);
            let mates = (_group_mates_u16.as_ref(), _sign_mates_u16.as_ref());
            let sign_keys = SignKeys::create(&private, inner_outer, idx_sign as u16, mates);
            sign_keys_batch.push(sign_keys);
        }

        let mut com_batch: Vec<SignBroadcastPhase1> = Vec::with_capacity(NB);
        let mut decom_batch: Vec<SignDecommitPhase1> = Vec::with_capacity(NB);
        for sign_key in sign_keys_batch.iter() {
            let (com, decom) = sign_key.phase1_broadcast();
            com_batch.push(com);
            decom_batch.push(decom);
        }

        let mut purpose = "phase1 com";
        self.post_message(MpcPeer::All(), purpose, &com_batch)
            .await
            .catch_()?;
        let com_vec_batch: SparseVecBatch<SignBroadcastPhase1> =
            self.get_message(MpcPeer::All(), purpose).await.catch_()?;

        purpose = "phase1 decom";
        self.post_message(MpcPeer::All(), purpose, &decom_batch)
            .await
            .catch_()?;
        let decom_vec_batch: SparseVecBatch<SignDecommitPhase1> =
            self.get_message(MpcPeer::All(), purpose).await.catch_()?;

        purpose = "MtA/MtAwc (a) (b-1)";
        let dlog_stat_vec = keystore.dlog_stmt_vec.clone();
        let paillier_vec = keystore.paillier_keys.clone();
        let mut mak_send_vec_batch: SparseVecBatch<MessageA> = SparseVec::with_capacity(NS);
        for id in sign_mates.iter() {
            if *id == my_id {
                continue;
            }
            let mut mak_batch = Vec::with_capacity(NB);
            for sign_key in sign_keys_batch.iter() {
                let (mak, _) = MessageA::a(
                    &sign_key.k_i,
                    &keystore.party_keys.ek,
                    &dlog_stat_vec[&my_id],
                );
                mak_batch.push(mak);
            }
            self.post_message(MpcPeer::Member(*id), purpose, &mak_batch)
                .await
                .catch_()?;
            mak_send_vec_batch.insert(*id, mak_batch);
        }
        let mak_recv_vec_batch: SparseVecBatch<MessageA> = self
            .get_message(MpcPeer::WithinExcept(sign_mates.clone(), my_id), purpose)
            .await
            .catch_()?;

        // MtA/MtAwc (b-2) (c) (d)
        let mut mbg_send_vec: SparseVecBatch<MessageA> = SparseVec::with_capacity(NS);
        let mut beta_vec: SparseVecBatch<Scalar<Secp256k1>> = SparseVec::with_capacity(NS);
        let mut mbw_send_vec: SparseVecBatch<MessageB> = SparseVec::with_capacity(NS);
        let mut ni_vec: SparseVecBatch<Scalar<Secp256k1>> = SparseVec::with_capacity(NS);
        for id in sign_mates.iter() {
            if *id == my_id {
                continue;
            }
            let mut mbg_batch = Vec::with_capacity(NB);
            let mut beta_batch = Vec::with_capacity(NB);
            let mut mbw_batch = Vec::with_capacity(NB);
            let mut ni_batch = Vec::with_capacity(NB);
            for (seqno, sign_key) in sign_keys_batch.iter().enumerate() {
                let (mbg, bg, _, _) = MessageB::b(
                    &sign_key.gamma_i,
                    &paillier_vec[id],
                    mak_recv_vec_batch[id][seqno].clone(),
                    &dlog_stat_vec[id],
                    &dlog_stat_vec[&my_id],
                    crate::mta::MTAMode::MtA,
                )
                .catch(
                    "RangeProofFailed",
                    &format!("Invalid Alice proof of k_i at member_id={}", id),
                )?;
                let (mbw, bw, _, _) = MessageB::b(
                    &sign_key.w_i,
                    &paillier_vec[id],
                    mak_recv_vec_batch[id][seqno].clone(),
                    &dlog_stat_vec[id],
                    &dlog_stat_vec[&my_id],
                    crate::mta::MTAMode::MtAwc,
                )
                .catch(
                    "RangeProofFailed",
                    &format!("Invalid Alice proof of k_i at member_id={}", id),
                )?;
                mbg_batch.push(mbg);
                mbw_batch.push(mbw);
                beta_batch.push(bg);
                ni_batch.push(bw);
            }
        }

        let purpose = "paillier ciphertext mbg";
        for id in sign_mates.iter() {
            if *id == my_id {
                continue;
            }
            self.post_message(MpcPeer::Member(*id), purpose, &mbg_send_vec[id])
                .await
                .catch_()?;
        }
        let mbg_recv_vec: SparseVecBatch<MessageA> = self
            .get_message(MpcPeer::WithinExcept(sign_mates.clone(), my_id), purpose)
            .await
            .catch_()?;

        let purpose = "paillier ciphertext mbw";
        for id in sign_mates.iter() {
            if *id == my_id {
                continue;
            }
            self.post_message(MpcPeer::Member(*id), purpose, &mbw_send_vec[id])
                .await
                .catch_()?;
        }
        let mbw_recv_vec: SparseVecBatch<MessageB> = self
            .get_message(MpcPeer::WithinExcept(sign_mates.clone(), my_id), purpose)
            .await
            .catch_()?;

        // #region MtA (e) / MtAwc (e) (f)
        let mut alpha_vec: Vec<Scalar<Secp256k1>> = Vec::new();
        let mut miu_vec: Vec<Scalar<Secp256k1>> = Vec::new();
        let mut xi_com_inner_vec: SparseVec<Scalar<Secp256k1>> = SparseVec::with_capacity(NS);
        for id in group_mates.iter() {
            let group_
        }

        // #endregion

        Ok(signatures)
    }
}
