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
use luban_core::MpcClientMessenger;
use sha2::Sha256;
use std::collections::HashMap;
use xuanmi_base_support::*;

use super::{mta::*, party_i::*};
use crate::Error;
use crate::MTAMode::{MtA, MtAwc};
use crate::{
    ChildKeyDerivationFailed, DlogProofFailed, InvalidCommitment, InvalidConfigs, InvalidGamma,
    InvalidKeystore, InvalidMessage, InvalidQuarum, InvalidSecretKey, InvalidSignature,
    MissingCommitments, RangeProofFailed,
};

use super::{data_structure::KeyStore, hd, Signature};
pub fn algo_sign(
    server: &str,
    tr_uuid: &str,
    tcn_config: &[u16; 3],
    derive: &str,
    msg_hashed: &[u8],
    keystore: &KeyStore,
) -> Outcome<Signature> {
    if msg_hashed.len() > 64 {
        let mut msg = String::from("The sign algorithm **assumes** its input message be hashed.\n");
        msg += &format!("However, the algorithm received a message with length = {}, indicating the message is probably un-hashed.\n", msg_hashed.len());
        msg += "Did the caller forget to hash the message?";
        throw!(name = InvalidMessage, ctx = &msg);
    }

    // #region Validate configurations
    let (threshold, n_actual, n_keygen) = (tcn_config[0], tcn_config[1], tcn_config[2]);
    let (party_id, group_id) = (keystore.party_id, keystore.group_id);
    let group_config = &keystore.vss_scheme_vec.0[party_id as usize - 1].parameters;
    let group_division = keystore.group_division.clone();
    println!(
        "Start sign with threshold={}, n_actual={}, n_keygen={}, \n\tgroup_threshold={}, group_sharecount={}, group_id={}",
        threshold, n_actual, n_keygen, group_config.threshold, group_config.share_count, group_id,
    );
    let cond = threshold + 1 <= n_actual && n_actual <= n_keygen;
    if !cond {
        throw!(
            name = InvalidConfigs,
            ctx = &format!(
                "t/c/n config should satisfy t<c<=n.\n\tHowever, {}/{}/{} was provided",
                threshold, n_actual, n_keygen
            )
        );
    }
    // #endregion

    // #region Derive child keys
    let (tweak_sk, y_sum) = match derive.is_empty() {
        true => (Scalar::<Secp256k1>::zero(), keystore.y_sum.clone()),
        false => hd::algo_get_hd_key(derive, &keystore.y_sum, &keystore.chain_code).catch(
            ChildKeyDerivationFailed,
            &format!(
                "Failed to {} where server=\"{}\", uuid=\"{}\", n_keygen=\"{}\", threshold=\"{}\"",
                "get_hd_key", server, tr_uuid, n_keygen, threshold
            ),
        )?,
    };
    // #endregion

    // #region Signup for signing
    let messenger =
        MpcClientMessenger::signup(server, "sign", tr_uuid, threshold, n_actual, n_keygen)?;
    let my_id = messenger.my_id();
    println!(
        "MPC Server {} designated this party with\n\tparty_id={}, tr_uuid={}",
        server,
        my_id,
        messenger.uuid()
    );
    let exception_location = &format!(" (at party_id={}, tr_uuid={}).", my_id, messenger.uuid());
    let mut round: u16 = 0;
    // #endregion

    // #region Round: collect signer IDs and validate
    messenger.send_broadcast(my_id, round, &obj_to_json(&(party_id, group_id))?)?;
    let round_id_ans_vec = messenger.recv_broadcasts(my_id, n_actual, round);
    let mut sign_info_vec: Vec<(u16, u16)> = round_id_ans_vec
        .iter()
        .map(|text| json_to_obj(text))
        .collect::<Result<Vec<(u16, u16)>, _>>()?;
    let mut signer_vec = sign_info_vec.iter().map(|x| x.0 - 1).collect::<Vec<_>>();
    // The algorithm ensured that in "normal" cases, signers_vec
    // (1) have no duplicates, and
    // (2) `keystore.party_id` of current party is not present.
    // Therefore, if a signer equals party_id-1, there should be a duplicate share.
    if signer_vec.contains(&(party_id - 1)) {
        throw!(
            name = InvalidKeystore,
            ctx = &(format!("Duplicated keyshare") + exception_location)
        );
    }
    signer_vec.insert(my_id as usize - 1, party_id - 1); // party_id - 1
    sign_info_vec.insert(my_id as usize - 1, (party_id, group_id)); // party_id

    let mut group_id_list = sign_info_vec.iter().map(|x| x.1).collect::<Vec<_>>();
    group_id_list.sort();
    group_id_list.dedup();
    let mut expected_group_id_list = group_division.keys().map(|s| *s).collect::<Vec<u16>>();
    expected_group_id_list.sort();
    if group_id_list != expected_group_id_list {
        throw!(
            name = InvalidQuarum,
            ctx = &(format!("Missing or nonexistent group ids")
                + exception_location
                + &format!(
                    "\n\tExpected group ids are {:?}, while given are {:?}.",
                    expected_group_id_list, group_id_list
                ))
        );
    }
    let group_signers: HashMap<u16, Vec<u16>> = group_id_list
        .iter()
        .filter_map(|id| {
            let group_signers_vec = sign_info_vec
                .iter()
                .filter(|x| x.1 == *id)
                .map(|x| x.0 - 1)
                .collect::<Vec<_>>();
            Some((*id, group_signers_vec))
        })
        .collect();
    let this_group = group_signers.get(&group_id).cloned().unwrap_or_default();
    if !(usize::from(group_config.threshold) < this_group.len()
        && this_group.len() <= group_config.share_count as usize)
    {
        throw!(
            name = InvalidConfigs,
            ctx = &(format!(
                "t/c/n group_config should satisfy t<c<=n.\n\tHowever, {}/{}/{} was provided",
                group_config.threshold,
                this_group.len(),
                group_config.share_count
            ) + exception_location)
        );
    }
    println!("Finished sign round: IDs collection and validation");
    round += 1;
    // #endregion

    // #region Round: send commitment
    // to be practically tricky, only applicable to sign
    // (1) ignore sign_at_path
    // (2) omit updates for all ui
    // (3) only update u1 * G as (u1 + tweak_sk) * G and all xi as (xi + tweak_sk)
    let mut vss_scheme_vec_outer = keystore.vss_scheme_vec.1.clone();
    vss_scheme_vec_outer[signer_vec[0] as usize].commitments[0] =
        vss_scheme_vec_outer[signer_vec[0] as usize].commitments[0].clone()
            + Point::generator() * &tweak_sk;
    let mut private =
        PartyPrivate::set_private(keystore.party_keys.clone(), keystore.shared_keys.clone());
    private = private.update_private_key(&Scalar::<Secp256k1>::zero(), &tweak_sk);

    let vss_scheme_vec_inner = keystore.vss_scheme_vec.0.clone();
    let sign_keys = SignKeys::create(
        &private,
        (
            &vss_scheme_vec_inner[usize::from(signer_vec[usize::from(my_id - 1)])],
            &vss_scheme_vec_outer[usize::from(signer_vec[usize::from(my_id - 1)])],
        ),
        party_id - 1,
        (&this_group, &signer_vec),
    );

    let (com, decommit) = sign_keys.phase1_broadcast();
    messenger.send_broadcast(my_id, round, &obj_to_json(&com.clone())?)?;
    let round_com_ans_vec = messenger.recv_broadcasts(my_id, n_actual, round);
    let mut bc1_vec: Vec<SignBroadcastPhase1> = Vec::new();
    format_vec_from_reads(
        &round_com_ans_vec,
        my_id as usize,
        com.clone(),
        &mut bc1_vec,
    )?;
    if signer_vec.len() != bc1_vec.len() {
        let ctx = format!(
            "Lengths of signer_vec ({}) and bc1_vec ({}) should be equal. \n\t Namely {} commitments of `gamma_i` are missing",
            signer_vec.len(),
            bc1_vec.len(),
            (signer_vec.len() - bc1_vec.len()),
        );
        throw!(name = MissingCommitments, ctx = &(ctx + exception_location));
    }
    println!("Finished sign round: commitments collection");
    round += 1;
    // #endregion

    // #region Round: do MtA/MtAwc (a) (b-1)
    let dlog_statement_vec = keystore.dlog_statement_vec.clone();
    let mut m_a_k_send_vec: Vec<MessageA> = Vec::new();
    let mut j = 0;
    for i in 1..=n_actual {
        if i != my_id {
            let (m_a_k, _) = MessageA::a(
                &sign_keys.k_i,
                &keystore.party_keys.ek,
                // &dlog_statement_vec[j],
                &dlog_statement_vec[usize::from(signer_vec[i as usize - 1])],
            );
            m_a_k_send_vec.push(m_a_k.clone());
            messenger.send_p2p(my_id, i, round, &obj_to_json(&m_a_k)?)?;
            j = j + 1;
        }
    }
    let round_ab1_ans_vec = messenger.gather_p2p(my_id, n_actual, round);
    let m_a_k_rec_vec: Vec<MessageA> = round_ab1_ans_vec
        .iter()
        .map(|text| json_to_obj(text))
        .collect::<Result<Vec<MessageA>, _>>()?;
    println!("Finished sign round: MtA/MtAwc initiation");
    round += 1;
    // #endregion

    // #region Do MtA/MtAwc (b-2) (c) (d)
    let mut m_b_gamma_send_vec: Vec<MessageB> = Vec::new();
    let mut beta_vec: Vec<Scalar<Secp256k1>> = Vec::new();
    let mut m_b_w_send_vec: Vec<MessageB> = Vec::new();
    let mut ni_vec: Vec<Scalar<Secp256k1>> = Vec::new();
    let mut j = 0;
    for i in 1..=n_actual {
        if i != my_id {
            let (m_b_gamma, beta_gamma, _, _) = match MessageB::b(
                &sign_keys.gamma_i,
                &keystore.paillier_key_vec[usize::from(signer_vec[usize::from(i - 1)])],
                m_a_k_rec_vec[j].clone(),
                // &dlog_statement_vec[j], // Alice
                &dlog_statement_vec[usize::from(signer_vec[i as usize - 1])], // Alice
                // &dlog_statement,        // Bob
                &dlog_statement_vec[usize::from(party_id) - 1], // Bob
                MtA,
            ) {
                Ok(__) => __,
                Err(_) => throw!(
                    name = RangeProofFailed,
                    ctx = &(format!("Invalid Alice's range proof of k_i where i={}", i)
                        + exception_location)
                ),
            };
            let (m_b_w, beta_wi, _, _) = match MessageB::b(
                &sign_keys.w_i,
                &keystore.paillier_key_vec[usize::from(signer_vec[usize::from(i - 1)])],
                m_a_k_rec_vec[j].clone(),
                // &dlog_statement_vec[j], // Alice
                &dlog_statement_vec[usize::from(signer_vec[i as usize - 1])], // Alice
                // &dlog_statement,        // Bob
                &dlog_statement_vec[usize::from(party_id) - 1], // Bob
                MtAwc,
            ) {
                Ok(__) => __,
                Err(_) => throw!(
                    name = RangeProofFailed,
                    ctx = &(format!("Invalid Alice's range proof of k_i where i={}", i)
                        + exception_location)
                ),
            };
            m_b_gamma_send_vec.push(m_b_gamma);
            m_b_w_send_vec.push(m_b_w);
            beta_vec.push(beta_gamma);
            ni_vec.push(beta_wi);
            j = j + 1;
        }
    }
    // #endregion

    // #region Round: send Paillier ciphertext
    let mut j = 0;
    for i in 1..=n_actual {
        if i != my_id {
            messenger.send_p2p(
                my_id,
                i,
                round,
                &obj_to_json(&(m_b_gamma_send_vec[j].clone(), m_b_w_send_vec[j].clone()))?,
            )?;
            j = j + 1;
        }
    }

    let round_plct_ans_vec = messenger.gather_p2p(my_id, n_actual, round);
    let (m_b_gamma_rec_vec, m_b_w_rec_vec): (Vec<MessageB>, Vec<MessageB>) = round_plct_ans_vec
        .iter()
        .map(|ans| json_to_obj(ans))
        .collect::<Result<Vec<(MessageB, MessageB)>, _>>()?
        .into_iter()
        .unzip();
    println!("Finished sign round: Paillier ciphertext exchange");
    round += 1;
    // #endregion

    // #region Do MtA (e) / MtAwc (e) (f)
    let mut alpha_vec: Vec<Scalar<Secp256k1>> = Vec::new();
    let mut miu_vec: Vec<Scalar<Secp256k1>> = Vec::new();

    let mut xi_com_vec_inner: Vec<Point<Secp256k1>> =
        vec![Point::<Secp256k1>::zero(); n_actual as usize]; // len of parties, corresponds to signer_vec / sign_info_vec
    for (g_id, g_signers_vec) in group_signers.iter() {
        let group_member_list = group_division.get(g_id).if_none(
            InvalidQuarum,
            &(format!("Group_id ({}) not found in group_division", g_id) + exception_location),
        )?;
        let group_vss_scheme_vec = group_member_list
            .iter()
            .map(|x| vss_scheme_vec_inner[*x as usize].clone())
            .collect::<Vec<_>>();
        let group_xi_com_vec = get_commitments_to_xi_given_n(n_keygen, &group_vss_scheme_vec);
        for &signer in g_signers_vec.iter() {
            let pos = signer_vec.iter().position(|&e| e == signer).if_none(
                InvalidQuarum,
                &(format!("Element ({}) not found in signer_vec", signer) + exception_location),
            )?;
            xi_com_vec_inner[pos] = group_xi_com_vec[signer as usize].clone();
        }
    }

    let xi_com_vec_outer = Keys::get_commitments_to_xi(&vss_scheme_vec_outer); // len of share_count

    for (j, (i, (m_b_gamma_rec, m_b_w_rec))) in (1..=n_actual)
        .filter(|&i| i != my_id)
        .zip(m_b_gamma_rec_vec.iter().zip(m_b_w_rec_vec.iter()))
        .enumerate()
    {
        let current_group = group_signers
            .get(&sign_info_vec[usize::from(i - 1)].1)
            .if_none(
                InvalidQuarum,
                &(format!(
                    "Group_id ({}) not found in group_signers",
                    sign_info_vec[usize::from(i - 1)].1
                ) + exception_location),
            )?;
        let g_w_i_inner = Keys::update_commitments_to_xi(
            &xi_com_vec_inner[usize::from(i - 1)],
            &vss_scheme_vec_inner[usize::from(signer_vec[usize::from(i - 1)])],
            sign_info_vec[usize::from(i - 1)].0 - 1,
            &current_group,
        );
        let g_w_i_outer = Keys::update_commitments_to_xi(
            &xi_com_vec_outer[usize::from(signer_vec[usize::from(i - 1)])],
            &vss_scheme_vec_outer[usize::from(signer_vec[usize::from(i - 1)])],
            sign_info_vec[usize::from(i - 1)].0 - 1,
            &signer_vec,
        );
        let g_w_i = g_w_i_inner + g_w_i_outer;
        if m_b_w_rec.b_proof.pk.clone() != g_w_i {
            throw!(
                name = DlogProofFailed,
                ctx = &(format!("Wrong dlog proof of w_i") + exception_location)
            );
        }

        let alpha_ij_gamma = match m_b_gamma_rec.verify_proofs_get_alpha(
            &keystore.party_keys.dk,
            m_a_k_send_vec[j].clone(),
            // &dlog_statement,         // Alice
            &dlog_statement_vec[usize::from(party_id) - 1], // Alice
            &keystore.party_keys.ek,                        // Alice
            &g_w_i,                                         // useless
        ) {
            Ok(v) => v,
            Err(__) => throw!(
                name = RangeProofFailed,
                ctx = &(format!("Invalid Bob's MtA range proof from party {}", i)
                    + exception_location)
            ),
        };

        let alpha_ij_wi = match m_b_w_rec.verify_proofs_get_alpha(
            &keystore.party_keys.dk,
            m_a_k_send_vec[j].clone(),
            // &dlog_statement,         // Alice
            &dlog_statement_vec[usize::from(party_id) - 1], // Alice
            &keystore.party_keys.ek,                        // Alice
            &g_w_i,
        ) {
            Ok(v) => v,
            Err(__) => throw!(
                name = RangeProofFailed,
                ctx = &(format!("Invalid Bob's MtAwc range proof from party {}", i)
                    + exception_location)
            ),
        };

        alpha_vec.push(alpha_ij_gamma.0);
        miu_vec.push(alpha_ij_wi.0);
    }
    let delta_i = sign_keys.phase2_delta_i(&alpha_vec, &beta_vec);
    let sigma = sign_keys.phase2_sigma_i(&miu_vec, &ni_vec);
    println!("Finished MtA / MtAwc");
    // #endregion

    // #region Round: send delta_i
    messenger.send_broadcast(my_id, round, &obj_to_json(&delta_i)?)?;
    let round_delta_ans_vec = messenger.recv_broadcasts(my_id, n_actual, round);
    let mut delta_vec: Vec<Scalar<Secp256k1>> = Vec::new();
    format_vec_from_reads(
        &round_delta_ans_vec,
        my_id as usize,
        delta_i,
        &mut delta_vec,
    )?;
    let delta_inv = SignKeys::phase3_reconstruct_delta(&delta_vec);
    println!("Finished sign round: `delta_i` collection");
    round += 1;
    // #endregion

    // #region Round: send decommitment to and zkp of gamma_i
    messenger.send_broadcast(my_id, round, &obj_to_json(&decommit)?)?;
    let round_decom_ans_vec = messenger.recv_broadcasts(my_id, n_actual, round);
    let mut decommit_vec: Vec<SignDecommitPhase1> = Vec::new();
    format_vec_from_reads(
        &round_decom_ans_vec,
        my_id as usize,
        decommit,
        &mut decommit_vec,
    )?;
    let decomm_i = decommit_vec.remove((my_id - 1) as usize);
    let _ = bc1_vec.remove((my_id - 1) as usize);
    // b_proof_vec contains all zkp of gamma_i using Schnorr's protocol
    let b_proof_vec = (0..m_b_gamma_rec_vec.len())
        .map(|i| &m_b_gamma_rec_vec[i].b_proof)
        .collect::<Vec<&DLogProof<Secp256k1, Sha256>>>();
    // phase 4 verifies decommitments and zkp of gamma_i
    let R = match SignKeys::phase4(&delta_inv, &b_proof_vec, decommit_vec, &bc1_vec) {
        Ok(__) => __,
        Err(_) => throw!(
            name = InvalidGamma,
            ctx = &("Either invalid commitment to or invalid zkp of `gamma_i` in `Phase4`"
                .to_owned()
                + exception_location)
        ),
    };
    let R = R + decomm_i.g_gamma_i * &delta_inv; // add local g_gamma_i
    println!("Finished sign round: `gamma_i`'s decommitment and zkp collection and validation");
    round += 1;
    // #endregion

    // #region Round: GG18 Phase 5A
    let message_bn = BigInt::from_bytes(msg_hashed);
    let two = BigInt::from(2);
    let message_bn = message_bn.modulus(&two.pow(256));

    let local_sig =
        LocalSignature::phase5_local_sig(&sign_keys.k_i, &message_bn, &R, &sigma, &y_sum);

    let (phase5_com, phase_5a_decom, helgamal_proof, dlog_proof_rho) =
        local_sig.phase5a_broadcast_5b_zkproof();
    messenger.send_broadcast(my_id, round, &obj_to_json(&phase5_com)?)?;
    let round_5a_ans_vec = messenger.recv_broadcasts(my_id, n_actual, round);
    let mut commit5a_vec: Vec<Phase5Com1> = Vec::new();
    format_vec_from_reads(
        &round_5a_ans_vec,
        my_id.clone() as usize,
        phase5_com,
        &mut commit5a_vec,
    )?;
    println!("Finished sign round: GG18 Phase `5A`");
    round += 1;
    // #endregion

    // #region Round: GG18 Phase 5B
    messenger.send_broadcast(
        my_id,
        round,
        &obj_to_json(&(
            phase_5a_decom.clone(),
            helgamal_proof.clone(),
            dlog_proof_rho.clone(),
        ))?,
    )?;
    let round_5b_ans_vec = messenger.recv_broadcasts(my_id, n_actual, round);
    let mut decommit5a_and_elgamal_and_dlog_vec: Vec<(
        Phase5ADecom1,
        HomoELGamalProof<Secp256k1, Sha256>,
        DLogProof<Secp256k1, Sha256>,
    )> = Vec::new();
    format_vec_from_reads(
        &round_5b_ans_vec,
        my_id as usize,
        (
            phase_5a_decom.clone(),
            helgamal_proof.clone(),
            dlog_proof_rho.clone(),
        ),
        &mut decommit5a_and_elgamal_and_dlog_vec,
    )?;
    let decommit5a_and_elgamal_vec_includes_i = decommit5a_and_elgamal_and_dlog_vec.clone();
    let _ = decommit5a_and_elgamal_and_dlog_vec.remove((my_id - 1) as usize);
    let _ = commit5a_vec.remove((my_id - 1) as usize);
    let (phase_5a_decomm_vec, phase_5a_elgamal_vec, phase_5a_dlog_vec): (
        Vec<Phase5ADecom1>,
        Vec<HomoELGamalProof<Secp256k1, Sha256>>,
        Vec<DLogProof<Secp256k1, Sha256>>,
    ) = decommit5a_and_elgamal_and_dlog_vec.into_iter().fold(
        (Vec::new(), Vec::new(), Vec::new()),
        |mut acc, (a, b, c)| {
            acc.0.push(a);
            acc.1.push(b);
            acc.2.push(c);
            acc
        },
    );

    let (phase5_com2, phase_5d_decom2) = match local_sig.phase5c(
        &phase_5a_decomm_vec,
        &commit5a_vec,
        &phase_5a_elgamal_vec,
        &phase_5a_dlog_vec,
        &phase_5a_decom.V_i,
        &R.clone(),
    ) {
        Ok(__) => __,
        Err(__) => throw!(
            name = InvalidCommitment,
            ctx = &(format!(
                "Invalid commitment to `(V,A,B)` or invalid zkp of `(s,l,rho)` in Phase `5C`"
            ) + exception_location)
        ),
    };
    println!("Finished sign round: GG18 Phase `5B`");
    round += 1;
    // #endregion

    // #region Round: GG18 Phase 5C
    messenger.send_broadcast(my_id, round, &obj_to_json(&phase5_com2)?)?;
    let round_5c_ans_vec = messenger.recv_broadcasts(my_id, n_actual, round);
    let mut commit5c_vec: Vec<Phase5Com2> = Vec::new();
    format_vec_from_reads(
        &round_5c_ans_vec,
        my_id.clone() as usize,
        phase5_com2,
        &mut commit5c_vec,
    )?;
    println!("Finished sign round: GG18 Phase `5C`");
    round += 1;
    // #endregion

    // #region Round: GG18 Phase 5D
    messenger.send_broadcast(my_id, round, &obj_to_json(&phase_5d_decom2)?)?;
    let round_5d_ans_vec = messenger.recv_broadcasts(my_id, n_actual, round);
    let mut decommit5d_vec: Vec<Phase5DDecom2> = Vec::new();
    format_vec_from_reads(
        &round_5d_ans_vec,
        my_id.clone() as usize,
        phase_5d_decom2.clone(),
        &mut decommit5d_vec,
    )?;

    let phase_5a_decomm_vec_includes_i = (0..n_actual)
        .map(|i| decommit5a_and_elgamal_vec_includes_i[i as usize].0.clone())
        .collect::<Vec<Phase5ADecom1>>();
    let s_i = match local_sig.phase5d(
        &decommit5d_vec,
        &commit5c_vec,
        &phase_5a_decomm_vec_includes_i,
    ) {
        Ok(__) => __,
        Err(e) => match e {
            Error::InvalidKey => throw!(
                name = InvalidSecretKey,
                ctx = &(format!("Invalid key in Phase `5D`") + exception_location)
            ),
            Error::InvalidCom => throw!(
                name = InvalidCommitment,
                ctx =
                    &(format!("Invalid commitment to `(U,T)` in Phase `5D`") + exception_location)
            ),
            __ => throw!(ctx = &("Unexpected error in Phase `5D`".to_owned() + exception_location)),
        },
    };
    println!("Finished sign round: GG18 Phase `5D`");
    round += 1;
    // #endregion

    // #region Round: GG18 Phase 5E
    messenger.send_broadcast(my_id, round, &obj_to_json(&s_i)?)?;
    let round_5e_ans_vec = messenger.recv_broadcasts(my_id, n_actual, round);
    let mut s_i_vec: Vec<Scalar<Secp256k1>> = Vec::new();
    format_vec_from_reads(&round_5e_ans_vec, my_id.clone() as usize, s_i, &mut s_i_vec)?;
    let _ = s_i_vec.remove((my_id - 1) as usize);
    let sig = match local_sig.output_signature(&s_i_vec) {
        Ok(__) => __,
        Err(__) => throw!(
            name = InvalidSignature,
            ctx = &(format!("Signature failed to pass verification") + exception_location)
        ),
    };
    check_sig(&sig.r, &sig.s, &message_bn, &y_sum).catch(InvalidSignature, "")?;
    println!("Finished sign round: GG18 Phase `5E`. Signature checked!");
    round += 1;
    // #endregion

    // #region Round: end mark
    let signature = Signature {
        sig_r: sig.r.clone(),
        sig_s: sig.s.clone(),
        recid: sig.recid,
        pk: y_sum.clone(),
        msg_hashed: Vec::from(msg_hashed),
    };
    messenger.send_broadcast(my_id, round, &signature.to_json()?)?;
    println!("Finished sign");
    // #endregion
    Ok(signature)
}

fn format_vec_from_reads<'a, T: serde::Deserialize<'a> + Clone>(
    ans_vec: &'a Vec<String>,
    party_num: usize,
    value_i: T,
    new_vec: &'a mut Vec<T>,
) -> Outcome<()> {
    let mut j = 0;
    for i in 1..ans_vec.len() + 2 {
        if i == party_num {
            new_vec.push(value_i.clone());
        } else {
            let value_j: T = json_to_obj(&ans_vec[j])?;
            new_vec.push(value_j);
            j = j + 1;
        }
    }
    Ok(())
}

// pub fn check_sig(
//     r: &Scalar<Secp256k1>,
//     s: &Scalar<Secp256k1>,
//     msg: &BigInt,
//     pk: &Point<Secp256k1>,
// ) -> Outcome<()> {
//     // input parameter msg is a hashed value of the raw message to be signed
//     let s_inv: Scalar<Secp256k1> = s.invert().unwrap_or_else(|| Scalar::<Secp256k1>::zero());
//     let r_prime =
//         (&s_inv * &Scalar::<Secp256k1>::from_bigint(&msg)) * Point::generator() + (r * &s_inv) * pk;
//     if r_prime.x_coord().unwrap_or_else(|| BigInt::from(0u16)) != r.to_bigint() {
//         throw!();
//     }
//     Ok(())
// }

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

    let msg = Message::from_slice(msg.as_slice()).unwrap();
    let mut raw_pk = pk.to_bytes(false).to_vec();
    if raw_pk.len() == 64 {
        raw_pk.insert(0, 4u8);
    }
    let pk = PublicKey::from_slice(&raw_pk).unwrap();

    let mut compact: Vec<u8> = Vec::new();
    let bytes_r = &r.to_bytes().to_vec();
    compact.extend(vec![0u8; 32 - bytes_r.len()]);
    compact.extend(bytes_r.iter());

    let bytes_s = &s.to_bytes().to_vec();
    compact.extend(vec![0u8; 32 - bytes_s.len()]);
    compact.extend(bytes_s.iter()); // compact = [r; s]

    let secp_sig = Signature::from_compact(compact.as_slice()).unwrap();

    if !SECP256K1.verify_ecdsa(&msg, &secp_sig, &pk).is_ok() {
        throw!();
    }
    Ok(())
}

pub fn scalar_split(num: &Scalar<Secp256k1>, count: &u16) -> Vec<Scalar<Secp256k1>> {
    let mut partition = (0..*count - 1)
        .map(|_| Scalar::<Secp256k1>::random())
        .collect::<Vec<_>>();
    partition.push(num - partition.iter().sum::<Scalar<Secp256k1>>());
    partition
}

pub fn get_commitments_to_xi_given_n(
    share_count: u16,
    vss_scheme_vec: &[VerifiableSS<Secp256k1>],
) -> Vec<Point<Secp256k1>> {
    (1..=share_count)
        .map(|i| {
            vss_scheme_vec
                .iter()
                .map(|vss| vss.get_point_commitment(i))
                .sum()
        })
        .collect()
}
