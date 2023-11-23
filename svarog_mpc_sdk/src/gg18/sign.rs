//! This is a modified version of `gg18_keygen_client.rs` of Kzen Networks' implementation of GG18 signing:
//! https://github.com/ZenGo-X/multi-party-ecdsa/blob/master/examples/gg18_sign_client.rs
//!

use std::collections::{HashMap, HashSet};

use bitcoin::bech32::Bech32Writer;
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
use svarog_grpc::protogen::svarog::{Signature, Signatures, TxHash};
use tonic::async_trait;
use xuanmi_base_support::*;

use super::*;
use crate::{
    mta::{MessageA, MessageB},
    util::*,
    mpc_member::*,
};

#[async_trait]
pub trait AlgoSign {
    async fn algo_sign(&self, keystore: &KeyStore, to_sign: &[TxHash]) -> Outcome<Vec<Signature>>;
}

#[async_trait]
impl AlgoSign for MpcMember {
    async fn algo_sign(&self, keystore: &KeyStore, to_sign: &[TxHash]) -> Outcome<Vec<Signature>> {
        let n_tx = to_sign.len();
        let my_id = self.member_id;
        let my_group_id = self.group_id;
        let key_mates: HashSet<usize> = self.member_group.keys().cloned().collect();
        let key_mates_wome = {
            // wome = without me
            let mut _km = key_mates.clone();
            _km.remove(&my_id);
            _km
        };
        let key_group_mates: HashSet<usize> =
            self.group_member[&self.group_id].iter().cloned().collect();
        let key_group_mates_wome = {
            let mut _gm = key_group_mates.clone();
            _gm.remove(&my_id);
            _gm
        };
        let sign_mates: HashSet<usize> = self.member_attending.iter().cloned().collect();
        let mut _sign_mates_u16: Vec<u16> = sign_mates.iter().map(|id| *id as u16).collect();
        _sign_mates_u16.sort();
        let sign_mates_wome = {
            let mut _sm = sign_mates.clone();
            _sm.remove(&my_id);
            _sm
        };
        let sign_mates_grouped: HashMap<usize, HashSet<usize>> = {
            let mut _smg = HashMap::new();
            for (group_id, member_ids) in self.group_member.iter() {
                let mut signer_in_group = HashSet::new();
                for member_id in member_ids.iter() {
                    if sign_mates.contains(member_id) {
                        signer_in_group.insert(*member_id);
                    }
                }
                if !signer_in_group.is_empty() {
                    _smg.insert(*group_id, signer_in_group);
                }
            }
            _smg
        };
        let sign_group_mates: HashSet<usize> = {
            let mut sgm = HashSet::new();
            for member_id in self.group_member[&my_group_id].iter() {
                if self.member_attending.contains(member_id) {
                    sgm.insert(*member_id);
                }
            }
            sgm
        };
        let mut _sign_group_mates_u16: Vec<u16> =
            sign_group_mates.iter().map(|id| *id as u16).collect();
        _sign_group_mates_u16.sort();

        let sign_group_mates_wome = {
            let mut _sgm = sign_group_mates.clone();
            _sgm.remove(&my_id);
            _sgm
        };
        let mut idx_group = 0;
        for (idx, member_id) in sign_group_mates.iter().enumerate() {
            if *member_id == self.member_id {
                idx_group = idx;
            }
        }
        let mut idx_sign = 0;
        for (idx, member_id) in sign_mates.iter().enumerate() {
            if *member_id == self.member_id {
                idx_sign = idx;
            }
        }

        let config = Parameters {
            threshold: (self.key_quorum - 1) as u16,
            share_count: key_mates.len() as u16,
        };
        let group_config = Parameters {
            threshold: (self.group_quora[&my_group_id] - 1) as u16,
            share_count: key_group_mates.len() as u16,
        };

        let mut signatures = Vec::new();
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
        let dk = &keystore.party_keys.dk;
        let ek = &keystore.party_keys.ek;
        let dlog_stmt_svec = keystore.dlog_stmt_vec.clone();
        let alice_dlog_stmt = &dlog_stmt_svec[&my_id];

        let (tweak_sk_batch, derv_pk_batch) = {
            let mut tweak_sk_batch = Vec::new();
            let mut derv_pk_batch = Vec::new();
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

        let member_id_first_signer = _sign_mates_u16[0] as usize;
        let vss_outer_svec = |tx_idx: usize| -> SparseVec<VerifiableSS<Secp256k1>> {
            // to be practically tricky, only applicable to sign
            // (1) ignore sign_at_path
            // (2) omit updates for all ui
            // (3) only update u1 * G as (u1 + tweak_sk) * G and all xi as (xi + tweak_sk)

            let mut v = keystore.vss_outer_vec.clone();
            let vv = v.get_mut(&member_id_first_signer).unwrap();
            vv.commitments[0] =
                vv.commitments[0].clone() + Point::generator() * tweak_sk_batch[tx_idx].clone();
            v
        };

        let vss_inner_svec = keystore.vss_inner_vec.clone();

        let mut sign_keys_batch = Vec::new();
        for (tx_idx, _) in to_sign.iter().enumerate() {
            let mut private = PartyPrivate::set_private(
                keystore.party_keys.clone(),
                keystore.shared_keys.clone(),
            );
            private =
                private.update_private_key(&Scalar::<Secp256k1>::zero(), &tweak_sk_batch[tx_idx]);
            let inner_outer = (&vss_inner_svec[&my_id], &vss_outer_svec(tx_idx)[&my_id]);
            let mates = (_sign_group_mates_u16.as_ref(), _sign_mates_u16.as_ref());
            let sign_keys = SignKeys::create(&private, inner_outer, idx_sign as u16, mates);
            sign_keys_batch.push(sign_keys);
        }

        let mut com_batch: Vec<SignBroadcastPhase1> = Vec::new();
        let mut decom_batch: Vec<SignDecommitPhase1> = Vec::new();
        for sign_key in sign_keys_batch.iter() {
            let (com, decom) = sign_key.phase1_broadcast();
            com_batch.push(com);
            decom_batch.push(decom);
        }

        let mut purpose = "phase1 com";
        self.postmsg_mcast(sign_mates.iter(), purpose, &com_batch)
            .await
            .catch_()?;
        let com_grid: Grid<SignBroadcastPhase1> = sparsevec_to_grid(
            &self
                .getmsg_mcast(sign_mates.iter(), purpose)
                .await
                .catch_()?,
        );

        purpose = "phase1 decom";
        self.postmsg_mcast(sign_mates.iter(), purpose, &decom_batch)
            .await
            .catch_()?;
        let decom_grid: Grid<SignDecommitPhase1> = sparsevec_to_grid(
            &self
                .getmsg_mcast(sign_mates.iter(), purpose)
                .await
                .catch_()?,
        );

        purpose = "MtA/MtAwc (a) (b-1)";
        let paillier_svec = keystore.paillier_keys.clone();
        let mut mak_send_grid: Grid<MessageA> = Grid::new();
        for member_id in sign_mates_wome.iter() {
            let mut mak_batch = Vec::new();
            for (tx_idx, sign_key) in sign_keys_batch.iter().enumerate() {
                let (mak, _) = MessageA::a(&sign_key.k_i, &ek, &dlog_stmt_svec[&my_id]);
                mak_batch.push(mak.clone());
                mak_send_grid.insert((*member_id, tx_idx), mak);
            }
            self.postmsg_p2p(*member_id, purpose, &mak_batch)
                .await
                .catch_()?;
        }
        let mak_recv_grid: Grid<MessageA> = sparsevec_to_grid(
            &self
                .getmsg_mcast(sign_mates_wome.iter(), purpose)
                .await
                .catch_()?,
        );

        // MtA/MtAwc (b-2) (c) (d)
        let mut mbg_send_svec_batch: SparseVec<Vec<MessageB>> = SparseVec::new();
        let mut beta_svec_batch: SparseVec<Vec<Scalar<Secp256k1>>> = SparseVec::new();
        let mut mbw_send_svec_batch: SparseVec<Vec<MessageB>> = SparseVec::new();
        let mut ni_svec_batch: SparseVec<Vec<Scalar<Secp256k1>>> = SparseVec::new();
        for member_id in sign_mates.iter() {
            if *member_id == my_id {
                continue;
            }
            let mut mbg_batch = Vec::new();
            let mut beta_batch = Vec::new();
            let mut mbw_batch = Vec::new();
            let mut ni_batch = Vec::new();
            for (tx_idx, sign_key) in sign_keys_batch.iter().enumerate() {
                let (mbg, bg, _, _) = MessageB::b(
                    &sign_key.gamma_i,
                    &paillier_svec[member_id],
                    mak_recv_grid[&(*member_id, tx_idx)].clone(),
                    &dlog_stmt_svec[member_id],
                    &dlog_stmt_svec[&my_id],
                    crate::mta::MTAMode::MtA,
                )
                .catch(
                    "RangeProofFailed",
                    &format!("Invalid Alice proof of k_i at member_id={}", member_id),
                )?;
                let (mbw, bw, _, _) = MessageB::b(
                    &sign_key.w_i,
                    &paillier_svec[member_id],
                    mak_recv_grid[&(*member_id, tx_idx)].clone(),
                    &dlog_stmt_svec[member_id],
                    &dlog_stmt_svec[&my_id],
                    crate::mta::MTAMode::MtAwc,
                )
                .catch(
                    "RangeProofFailed",
                    &format!("Invalid Alice proof of k_i at member_id={}", member_id),
                )?;
                mbg_batch.push(mbg);
                mbw_batch.push(mbw);
                beta_batch.push(bg);
                ni_batch.push(bw);
            }
            mbg_send_svec_batch.insert(*member_id, mbg_batch);
            mbw_send_svec_batch.insert(*member_id, mbw_batch);
            beta_svec_batch.insert(*member_id, beta_batch);
            ni_svec_batch.insert(*member_id, ni_batch);
        }

        let mbg_send_grid = sparsevec_to_grid(&mbg_send_svec_batch);
        let mbw_send_grid = sparsevec_to_grid(&mbw_send_svec_batch);
        let beta_grid = sparsevec_to_grid(&beta_svec_batch);
        let ni_grid = sparsevec_to_grid(&ni_svec_batch);

        let mut purpose = "paillier ciphertext mbg";
        for member_id in sign_mates_wome.iter() {
            self.postmsg_p2p(*member_id, purpose, &mbg_send_svec_batch[member_id])
                .await
                .catch_()?;
        }
        let mbg_recv_grid: Grid<MessageB> = sparsevec_to_grid(
            &self
                .getmsg_mcast(sign_mates_wome.iter(), purpose)
                .await
                .catch_()?,
        );

        purpose = "paillier ciphertext mbw";
        for member_id in sign_mates_wome.iter() {
            self.postmsg_p2p(*member_id, purpose, &mbw_send_svec_batch[member_id])
                .await
                .catch_()?;
        }
        let mbw_recv_grid: Grid<MessageB> = sparsevec_to_grid(
            &self
                .getmsg_mcast(sign_mates_wome.iter(), purpose)
                .await
                .catch_()?,
        );

        // #region MtA (e) / MtAwc (e) (f), which are final
        let mut xi_com_inner_svec: SparseVec<Point<Secp256k1>> = SparseVec::new();
        for (_, group_signers) in sign_mates_grouped.iter() {
            let group_vss_inner_svec: SparseVec<VerifiableSS<Secp256k1>> = group_signers
                .iter()
                .map(|id| (id.clone(), vss_inner_svec[id].clone()))
                .collect();
            let group_xi_com_svec: SparseVec<Point<Secp256k1>> = key_mates
                .iter()
                .map(|id| {
                    let v = group_vss_inner_svec
                        .iter()
                        .map(|(_, vss)| vss.get_point_commitment(*id as u16))
                        .sum();
                    (*id, v)
                })
                .collect();
            for signer in group_signers.iter() {
                xi_com_inner_svec.insert(*signer, group_xi_com_svec[signer].clone());
            }
        }

        let mut xi_com_outer_grid = Grid::new();

        for (tx_idx, _) in to_sign.iter().enumerate() {
            let _vss_outer_svec = vss_outer_svec(tx_idx);
            let _vss_outer_vec = _vss_outer_svec.values_sorted_by_key_asc();
            let _vss_outer_keys = _vss_outer_svec.keys_asc();
            let _len = _vss_outer_svec.len();
            let xi_com_outer_vec = Keys::get_commitments_to_xi(&_vss_outer_vec);
            for (i, xi_com_outer) in xi_com_outer_vec.iter().enumerate() {
                let member_id = _vss_outer_keys[i];
                xi_com_outer_grid.insert((member_id, tx_idx), xi_com_outer.clone());
            }
        }

        let mut gwi_grid = Grid::new();
        let mut alpha_grid = Grid::new();
        let mut mu_grid = Grid::new();

        for member_id in sign_mates.iter() {
            if *member_id == my_id {
                continue;
            }
            let mut current_group: Vec<usize> = sign_mates_grouped[&self.member_group[member_id]]
                .iter()
                .map(|x| x.clone())
                .collect();
            current_group.sort();
            let mut idx_sign: Option<usize> = None;
            for (idx, id) in _sign_mates_u16.iter().enumerate() {
                if *id == *member_id as u16 {
                    idx_sign = Some(idx);
                }
            }
            let idx_sign = idx_sign.ifnone_()?;
            let current_group_u16: Vec<u16> = current_group.iter().map(|x| *x as u16).collect();

            let gwi_inner: Point<Secp256k1> = Keys::update_commitments_to_xi(
                &xi_com_inner_svec[member_id],
                &vss_inner_svec[member_id],
                idx_sign as u16,
                &current_group_u16,
            );

            for tx_idx in 0..n_tx {
                let mbg = &mbg_recv_grid[&(*member_id, tx_idx)];
                let mbw = &mbw_recv_grid[&(*member_id, tx_idx)];
                let gwi_outer = Keys::update_commitments_to_xi(
                    &xi_com_outer_grid[&(*member_id, tx_idx)],
                    &vss_outer_svec(tx_idx)[member_id],
                    idx_sign as u16,
                    &current_group_u16,
                );
                let gwi = gwi_outer + &gwi_inner;
                assert_throw!(
                    mbg.b_proof.pk.clone() == gwi,
                    "DlogProofFailed",
                    "Wrong dlog proof of w_i"
                );
                gwi_grid.insert((*member_id, tx_idx), gwi.clone());

                let mak = mak_recv_grid[&(*member_id, tx_idx)].clone();
                let alpha_ij_gamma: Scalar<Secp256k1> = mbg
                    .verify_proofs_get_alpha(dk, mak.clone(), alice_dlog_stmt, ek, &gwi)
                    .catch(
                        "RangeProofFailed",
                        &format!("Invalid Bob's MtA range proof from party {}", member_id),
                    )?
                    .0;
                alpha_grid.insert((*member_id, tx_idx), alpha_ij_gamma);

                let alpha_ij_wi: Scalar<Secp256k1> = mbw
                    .verify_proofs_get_alpha(dk, mak, alice_dlog_stmt, ek, &gwi)
                    .catch(
                        "RangeProofFailed",
                        &format!("Invalid Bob's MtAwc range proof from party {}", member_id),
                    )?
                    .0;
                mu_grid.insert((*member_id, tx_idx), alpha_ij_wi);
            }
        }

        let mut delta_i_batch: Vec<Scalar<Secp256k1>> = Vec::new();
        let mut sigma_batch: Vec<Scalar<Secp256k1>> = Vec::new();
        for tx_idx in 0..n_tx {
            let mut alpha_svec = SparseVec::new();
            let mut beta_svec = SparseVec::new();
            let mut mu_svec = SparseVec::new();
            let mut ni_svec = SparseVec::new();

            for member_id in sign_mates.iter() {
                if *member_id == my_id {
                    continue;
                }
                let alpha = alpha_grid[&(*member_id, tx_idx)].clone();
                alpha_svec.insert(*member_id, alpha);
                let beta = beta_grid[&(*member_id, tx_idx)].clone();
                beta_svec.insert(*member_id, beta);
                let mu = mu_grid[&(*member_id, tx_idx)].clone();
                mu_svec.insert(*member_id, mu);
                let ni = ni_grid[&(*member_id, tx_idx)].clone();
                ni_svec.insert(*member_id, ni);
            }

            let alpha_vec = alpha_svec.values_sorted_by_key_asc();
            let beta_vec = beta_svec.values_sorted_by_key_asc();
            let mu_vec = mu_svec.values_sorted_by_key_asc();
            let ni_vec = ni_svec.values_sorted_by_key_asc();

            let delta_i = sign_keys_batch[tx_idx].phase2_delta_i(&alpha_vec, &beta_vec);
            delta_i_batch.push(delta_i);

            let sigma = sign_keys_batch[tx_idx].phase2_sigma_i(&mu_vec, &ni_vec);
            sigma_batch.push(sigma);
        }
        // #endregion MtA / MtAwc

        purpose = "delta_i";
        self.postmsg_mcast(sign_mates.iter(), purpose, &delta_i_batch)
            .await
            .catch_()?;
        let delta_i_grid: Grid<Scalar<Secp256k1>> = sparsevec_to_grid(
            &self
                .getmsg_mcast(sign_mates.iter(), purpose)
                .await
                .catch_()?,
        );
        let mut delta_inv_batch = Vec::new();
        for tx_idx in 0..n_tx {
            let mut delta_i_svec = SparseVec::new();
            for member_id in sign_mates.iter() {
                let delta_i = delta_i_grid[&(*member_id, tx_idx)].clone();
                delta_i_svec.insert(*member_id, delta_i);
            }
            let delta_vec = delta_i_svec.values_sorted_by_key_asc();
            let delta_inv = SignKeys::phase3_reconstruct_delta(&delta_vec);
            delta_inv_batch.push(delta_inv);
        }

        purpose = "decom";
        self.postmsg_mcast(sign_mates.iter(), purpose, &decom_batch)
            .await
            .catch_()?;
        let decom_grid: Grid<SignDecommitPhase1> = sparsevec_to_grid(
            &self
                .getmsg_mcast(sign_mates.iter(), purpose)
                .await
                .catch_()?,
        );

        let mut R_batch = Vec::new();
        for tx_idx in 0..n_tx {
            let mut decom_svec = SparseVec::new();
            let mut com_svec = SparseVec::new();
            let mut b_proof_svec = SparseVec::new();
            for member_id in sign_mates.iter() {
                if *member_id == my_id {
                    continue;
                }
                let decom = &decom_grid[&(*member_id, tx_idx)];
                decom_svec.insert(*member_id, decom.clone());
                let com = &com_grid[&(*member_id, tx_idx)];
                com_svec.insert(*member_id, com.clone());
                let b_proof = &mbg_recv_grid[&(*member_id, tx_idx)].b_proof;
                b_proof_svec.insert(*member_id, b_proof);
            }
            let decom_vec = decom_svec.values_sorted_by_key_asc();
            let com_vec = com_svec.values_sorted_by_key_asc();
            let b_proof_vec = b_proof_svec.values_sorted_by_key_asc();

            let delta_inv = &delta_inv_batch[tx_idx];
            let R: Point<Secp256k1> =
                SignKeys::phase4(delta_inv, &b_proof_vec, decom_vec, &com_vec).catch(
                    "InvalidGamma",
                    "Either invalid commitment to or invalid zkp of `gamma_i` in `Phase4`",
                )?;
            let R = R + decom_grid[&(my_id, tx_idx)].g_gamma_i.clone() * delta_inv;
            R_batch.push(R);
        }

        // GG18 Phase 5A
        let mut message_bn_batch = Vec::new();
        let mut local_sig_batch = Vec::new();
        for (tx_idx, tx_obj) in to_sign.iter().enumerate() {
            let message_bn = BigInt::from_bytes(&tx_obj.tx_hash);
            let two = BigInt::from(2);
            let message_bn = message_bn.modulus(&two.pow(256));
            message_bn_batch.push(message_bn.clone());

            let local_sig = LocalSignature::phase5_local_sig(
                &sign_keys_batch[tx_idx].k_i,
                &message_bn,
                &R_batch[tx_idx],
                &sigma_batch[tx_idx],
                &y_sum,
            );
            local_sig_batch.push(local_sig);
        }

        let mut phase5_com_batch = Vec::new();
        let mut phase5_decom_batch = Vec::new();
        let mut elgamal_proof_batch = Vec::new();
        let mut dlog_proof_rho_batch = Vec::new();
        for local_sig in local_sig_batch.iter() {
            let obj = local_sig.phase5a_broadcast_5b_zkproof();
            phase5_com_batch.push(obj.0);
            phase5_decom_batch.push(obj.1);
            elgamal_proof_batch.push(obj.2);
            dlog_proof_rho_batch.push(obj.3);
        }

        purpose = "phase5 com1";
        self.postmsg_mcast(sign_mates.iter(), purpose, &phase5_com_batch)
            .await
            .catch_()?;
        let commit5a_grid: Grid<Phase5Com1> = sparsevec_to_grid(
            &self
                .getmsg_mcast(sign_mates.iter(), purpose)
                .await
                .catch_()?,
        );

        purpose = "phase5 decom1";
        self.postmsg_mcast(sign_mates.iter(), purpose, &phase5_decom_batch)
            .await
            .catch_()?;
        let phase5_decom_grid: Grid<Phase5ADecom1> = sparsevec_to_grid(
            &self
                .getmsg_mcast(sign_mates.iter(), purpose)
                .await
                .catch_()?,
        );

        purpose = "phase5 elgamal proof";
        self.postmsg_mcast(sign_mates.iter(), purpose, &elgamal_proof_batch)
            .await
            .catch_()?;
        let phase5_elgamal_grid: Grid<HomoELGamalProof<Secp256k1, Sha256>> = sparsevec_to_grid(
            &self
                .getmsg_mcast(sign_mates.iter(), purpose)
                .await
                .catch_()?,
        );

        purpose = "phase5 dlog proof";
        self.postmsg_mcast(sign_mates.iter(), purpose, &dlog_proof_rho_batch)
            .await
            .catch_()?;
        let phase5_dlog_grid: Grid<DLogProof<Secp256k1, Sha256>> = sparsevec_to_grid(
            &self
                .getmsg_mcast(sign_mates.iter(), purpose)
                .await
                .catch_()?,
        );

        let mut phase5_com2_batch = Vec::new();
        let mut phase5_decom2_batch = Vec::new();
        for (tx_idx, local_sig) in local_sig_batch.iter().enumerate() {
            let mut decom_svec = SparseVec::new();
            let mut com_svec = SparseVec::new();
            let mut elgamal_svec = SparseVec::new();
            let mut dlog_svec = SparseVec::new();
            for member_id in sign_mates.iter() {
                if *member_id == my_id {
                    continue;
                }
                let decom = &phase5_decom_grid[&(*member_id, 0)];
                decom_svec.insert(*member_id, decom.clone());
                let com = &commit5a_grid[&(*member_id, 0)];
                com_svec.insert(*member_id, com.clone());
                let elgamal = &phase5_elgamal_grid[&(*member_id, 0)];
                elgamal_svec.insert(*member_id, elgamal.clone());
                let dlog = &phase5_dlog_grid[&(*member_id, 0)];
                dlog_svec.insert(*member_id, dlog.clone());
            }
            let decom_vec = decom_svec.values_sorted_by_key_asc();
            let com_vec = com_svec.values_sorted_by_key_asc();
            let elgamal_vec = elgamal_svec.values_sorted_by_key_asc();
            let dlog_vec = dlog_svec.values_sorted_by_key_asc();

            let obj = local_sig
                .phase5c(
                    &decom_vec,
                    &com_vec,
                    &elgamal_vec,
                    &dlog_vec,
                    &phase5_decom_batch[tx_idx].V_i,
                    &R_batch[tx_idx],
                )
                .catch(
                    "InvalidCommitment",
                    "Invalid commitment to `(V,A,B)` or invalid zkp of `(s,l,rho)` in Phase `5C`",
                )?;
            phase5_com2_batch.push(obj.0);
            phase5_decom2_batch.push(obj.1);
        }

        purpose = "phase5 com2";
        self.postmsg_mcast(sign_mates.iter(), purpose, &phase5_com2_batch)
            .await
            .catch_()?;
        let commit5c_grid: HashMap<(usize, usize), Phase5Com2> = sparsevec_to_grid(
            &self
                .getmsg_mcast(sign_mates.iter(), purpose)
                .await
                .catch_()?,
        );

        purpose = "phase5 decom2";
        self.postmsg_mcast(sign_mates.iter(), purpose, &phase5_decom2_batch)
            .await
            .catch_()?;
        let decom5d_grid: HashMap<(usize, usize), Phase5DDecom2> = sparsevec_to_grid(
            &self
                .getmsg_mcast(sign_mates.iter(), purpose)
                .await
                .catch_()?,
        );

        let mut s_i_batch = Vec::new();
        for (tx_idx, local_sig) in local_sig_batch.iter().enumerate() {
            let mut decom5d_svec = SparseVec::new();
            let mut com5c_svec = SparseVec::new();
            let mut decom5a_svec = SparseVec::new();
            for member_id in sign_mates.iter() {
                let decom5d = &decom5d_grid[&(*member_id, tx_idx)];
                let com5c = &commit5c_grid[&(*member_id, tx_idx)];
                let decom5a = &phase5_decom_grid[&(*member_id, tx_idx)];
                decom5d_svec.insert(*member_id, decom5d.clone());
                com5c_svec.insert(*member_id, com5c.clone());
                decom5a_svec.insert(*member_id, decom5a.clone());
            }
            let decom5d_vec = decom5d_svec.values_sorted_by_key_asc();
            let com5c_vec = com5c_svec.values_sorted_by_key_asc();
            let decom5a_vec = decom5a_svec.values_sorted_by_key_asc();

            // Possible failures:
            // Invalid key in phase 5d
            // Invalid commitment to `(U,T)` in Phase `5D`
            let s_i = local_sig
                .phase5d(&decom5d_vec, &com5c_vec, &decom5a_vec)
                .catch_()?;
            s_i_batch.push(s_i);
        }

        purpose = "phase5e";
        self.postmsg_mcast(sign_mates_wome.iter(), purpose, &s_i_batch)
            .await
            .catch_()?;
        let s_i_grid: Grid<Scalar<Secp256k1>> = sparsevec_to_grid(
            &self
                .getmsg_mcast(sign_mates_wome.iter(), purpose)
                .await
                .catch_()?,
        );

        let mut fruit = Signatures::default();
        for (tx_idx, local_sig) in local_sig_batch.iter().enumerate() {
            let mut s_i_svec = SparseVec::new();
            for member_id in sign_mates_wome.iter() {
                let s_i = s_i_grid[&(*member_id, tx_idx)].clone();
                s_i_svec.insert(*member_id, s_i);
            }
            let s_i_vec = s_i_svec.values_sorted_by_key_asc();
            let sig = local_sig
                .output_signature(&s_i_vec)
                .catch("InvalidSignature", "Signature failed to pass verification")?;
            check_sig(&sig.r, &sig.s, &message_bn_batch[tx_idx], &y_sum)
                .catch("InvalidSignature", "")?;
            let sig_pb = svarog_grpc::protogen::svarog::Signature {
                r: sig.r.to_bytes().to_vec(),
                s: sig.s.to_bytes().to_vec(),
                v: sig.recid == 1,
                derive_path: to_sign[tx_idx].derive_path.clone(),
                tx_hash: to_sign[tx_idx].tx_hash.clone(),
            };
            fruit.signatures.push(sig_pb);
        }
        let fruit = SessionFruitValue::Signatures(fruit);

        self.terminate_session(fruit).await.catch_()?;

        Ok(signatures)
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
