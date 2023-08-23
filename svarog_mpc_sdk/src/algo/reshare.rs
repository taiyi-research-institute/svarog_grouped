use std::collections::HashMap;
// reshare under (t,n)-scheme
// m ( n <= m <= 2 * n) parties involved, ONLY n parties receive new shares
// t' (t' > t) parties give x_i
// we don't support any threshold == -1 case
// we also don't support any group_id == 0 case
// t, n, t_1, n_1, ..., t_m, n_m, m are fixed rather than dynamic
use std::convert::TryInto;
use std::iter::zip;
use std::ops::Deref;

use bip32::ChainCode;
use bip39::{Language, Mnemonic};
use curv::{
    arithmetic::traits::Converter,
    cryptographic_primitives::{
        commitments::{hash_commitment::HashCommitment, traits::Commitment},
        proofs::sigma_dlog::DLogProof,
        secret_sharing::feldman_vss::{ShamirSecretSharing, VerifiableSS},
    },
    elliptic::curves::{secp256_k1::Secp256k1, Point, Scalar},
    BigInt,
};
use hex;
use luban_core::*;
use paillier::EncryptionKey;
use sha2::{Digest, Sha256, Sha512};
use xuanmi_base_support::*;
use zk_paillier::zkproofs::DLogStatement;

use crate::algo::{
    data_structure::KeyStore,
    mta::range_proofs::{ZkpPublicSetup, ZkpSetup, DEFAULT_GROUP_ORDER_BIT_LENGTH},
};
use crate::{
    scalar_split, ChildKeyDerivationFailed, DlogProofFailed, InvalidACK, InvalidConfigs,
    InvalidRangeProofSetup, InvalidSecretKey, PaillierKeyProofs, SignUpFailed,
};

use super::aes;
use super::party_i::{KeyGenBroadcastMessage1, KeyGenDecommitMessage1, Keys, SharedKeys};
type KeygenT = (String, KeyStore); // (mnemonic, keystore_json)
                                   // const EX: &'static str = "KeygenException";

pub fn algo_reshare(
    server: &str,
    tr_uuid: &str,
    tcn_config: &[u16; 6],       // Mandatory
    roles: &[bool; 2],           // Mandatory
    keystore: Option<&KeyStore>, // Optional, only givers have access
) -> Outcome<KeygenT> {
    // #region Validate configurations
    // parties: all parties that either contribute or receive shares
    let (if_give, if_receive) = (roles[0], roles[1]); // if give x_i, if receive new shares
    if !(if_give || if_receive) {
        throw!(
            name = InvalidConfigs,
            ctx = "Should at least be either a giver or a receiver."
        );
    }
    if if_give != keystore.is_some() {
        throw!(
            name = InvalidConfigs,
            ctx = "(Non-)Givers should have (no) access to keystores."
        );
    }

    let (threshold, parties, share_count, group_threshold, group_share_count, group_id) = (
        tcn_config[0],
        tcn_config[1],
        tcn_config[2],
        tcn_config[3],
        tcn_config[4],
        tcn_config[5],
    );

    let cond = threshold + 1 <= parties
        && parties >= share_count
        && group_threshold + 1 <= group_share_count;
    if !cond {
        throw!(
            name = InvalidConfigs,
            ctx = &format!(
                "t/c/n and gt/gn config should satisfy t<c<=n and gt<gn.\n\tHowever, {}/{}/{} and {}/{} was provided",
                threshold, parties, share_count, group_threshold, group_share_count
            )
        );
    }

    let mut round: u16 = 0;
    let (if_give_str, if_receive_str) = (["Non-giver", "Giver"], ["Non-receiver", "Receiver"]);
    println!(
        "Start reshare with threshold={}, parties={}, share_count={}, \n\tgroup_threshold={}, group_share_count={}, group_id={},\n\t roles={}, {}.",
        threshold, parties, share_count, group_threshold, group_share_count, group_id,
        if_give_str[if_give as usize], if_receive_str[if_receive as usize],
    );

    let messenger =
        MpcClientMessenger::signup(server, "keygen", tr_uuid, threshold, parties, share_count)
            .catch(
                SignUpFailed,
                &format!(
                    "Cannot sign up for reshare with server={}, tr_uuid={}.",
                    server, tr_uuid
                ),
            )?;
    let my_id = messenger.my_id();
    println!(
        "MPC Server \"{}\" designated this party with \n\tparty_id={}, tr_uuid={}",
        server,
        my_id,
        messenger.uuid()
    );
    let exception_location = &format!(" (at party_id={}, tr_uuid={}).", my_id, messenger.uuid());
    // #endregion

    // initialization
    let mut shared_keys = SharedKeys {
        y: Point::<Secp256k1>::zero(),
        x_i: (Scalar::<Secp256k1>::random(), Scalar::<Secp256k1>::random()),
    };
    let mut party_id = parties + 1;
    let vss_scheme_zero = VerifiableSS::<Secp256k1> {
        parameters: ShamirSecretSharing {
            threshold,
            share_count,
        },
        commitments: vec![Point::<Secp256k1>::zero(); threshold as usize + 1],
    };

    // read data from keys file
    if if_give {
        shared_keys = keystore.unwrap().shared_keys.clone();
        party_id = keystore.unwrap().party_id;

        let expected_group_id = keystore.unwrap().group_id;
        let expected_group_config =
            &keystore.unwrap().vss_scheme_vec.0[party_id as usize - 1].parameters;
        if group_id != expected_group_id
            || group_threshold != expected_group_config.threshold
            || group_share_count != expected_group_config.share_count
        {
            throw!(
                name = InvalidConfigs,
                ctx = &format!(
                    "group config (gt/gn/id = {}/{}/{}) don't match with keystore ({}/{}/{})",
                    group_threshold,
                    group_share_count,
                    group_id,
                    expected_group_config.threshold,
                    expected_group_config.share_count,
                    expected_group_id,
                )
            );
        }
    }

    // #region Round: info collection
    messenger.send_broadcast(
        my_id,
        round,
        &obj_to_json(&(
            my_id,
            party_id,
            if_give,
            if_receive,
            group_threshold,
            group_share_count,
            group_id,
        ))?,
    )?;
    let round_info_ans_vec = messenger.recv_broadcasts(0u16, parties, round);
    println!("Finished reshare round: info collection");
    round += 1;
    // #endregion

    // #region Parse and validate information
    let reshare_info_vec: Vec<(u16, u16, bool, bool, u16, u16, u16)> = round_info_ans_vec
        .iter()
        .map(|text| json_to_obj(text))
        .collect::<Result<Vec<_>, _>>()?;

    let (givers_vec, mut givers_group_id): (Vec<_>, Vec<_>) = reshare_info_vec
        .iter()
        .filter(|x| x.2)
        .map(|x| (x.0, x.6)) // my_id
        .unzip();
    let (receivers_vec, mut receivers_group_id): (Vec<_>, Vec<_>) = reshare_info_vec
        .iter()
        .filter(|x| x.3)
        .map(|x| (x.0, x.6)) // my_id
        .unzip();

    let givers: u16 = givers_vec.len() as u16;
    if givers_vec.len() <= threshold as usize
        || givers_vec.len() > share_count as usize
        || receivers_vec.len() != share_count as usize
    {
        throw!(
            name = InvalidConfigs,
            ctx = &format!(
                "Expected giver amount is > {} and <= {}, while {} is provided.\n\t
                Expected receiver amount is = {}, while {} is provided.",
                threshold,
                share_count,
                givers_vec.len(),
                share_count,
                receivers_vec.len(),
            )
        );
    }

    givers_group_id.sort();
    receivers_group_id.sort();
    givers_group_id.dedup();
    receivers_group_id.dedup();
    if if_give {
        let mut expected_group_ids = keystore
            .unwrap()
            .group_division
            .keys()
            .map(|s| *s)
            .collect::<Vec<u16>>();
        expected_group_ids.sort();
        if expected_group_ids != givers_group_id || expected_group_ids != receivers_group_id {
            throw!(
                name = InvalidConfigs,
                ctx = &format!(
                    "All expected group ids are {:?}. However, {:?} are provided by givers and {:?} by receivers.",
                    expected_group_ids, givers_group_id, receivers_group_id,
                )
            );
        }
    }

    let mut givers_division: HashMap<u16, Vec<u16>> = HashMap::new();
    let mut receivers_division: HashMap<u16, Vec<u16>> = HashMap::new();
    let mut group_division: HashMap<u16, Vec<u16>> = HashMap::new();
    for id in givers_group_id.iter() {
        let one_division: Vec<u16> = reshare_info_vec
            .iter()
            .filter(|x| x.2 && x.6 == *id)
            .map(|x| x.0) // my_id
            .collect();
        givers_division.insert(*id, one_division);
    }
    for id in receivers_group_id.iter() {
        let one_division: Vec<_> = reshare_info_vec
            .iter()
            .filter(|x| x.3 && x.6 == *id)
            .map(|x| x.0) // my_id
            .collect();
        let reordered: Vec<_> = one_division
            .iter()
            .map(|x| receivers_vec.iter().position(|&y| y == *x).unwrap() as u16)
            .collect();
        receivers_division.insert(*id, one_division);
        group_division.insert(*id, reordered);
    }

    let this_group_givers = givers_division.get(&group_id).unwrap();
    let this_group_receivers = receivers_division.get(&group_id).unwrap();
    if this_group_givers.len() <= group_threshold as usize
        || this_group_givers.len() > group_share_count as usize
        || this_group_receivers.len() != group_share_count as usize
    {
        throw!(
            name = InvalidConfigs,
            ctx = &format!(
                "Expected length of this giver group is > {} and <= {}, while {} is provided.\n\t
                Expected length of this receiver group is = {}, while {} is provided.",
                group_threshold,
                group_share_count,
                this_group_givers.len(),
                group_share_count,
                this_group_receivers.len(),
            )
        );
    }

    let this_group_givers_pid: Vec<u16> = reshare_info_vec
        .iter()
        .filter(|x| x.2 && x.6 == group_id)
        .map(|x| x.1 - 1)
        .collect();
    let givers_pid_vec: Vec<u16> = reshare_info_vec
        .iter()
        .filter(|x| x.2)
        .map(|x| x.1 - 1)
        .collect();
    // #endregion

    // #region Derive w_i from x_i and split
    let (mut w_i_inner, mut w_i_outer) =
        (Scalar::<Secp256k1>::random(), Scalar::<Secp256k1>::random());

    if if_give {
        let lambda_inner = VerifiableSS::<Secp256k1>::map_share_to_new_params(
            &ShamirSecretSharing {
                threshold: group_threshold,
                share_count: group_share_count,
            },
            party_id - 1,
            &this_group_givers_pid,
        );
        let lambda_outer = VerifiableSS::<Secp256k1>::map_share_to_new_params(
            &ShamirSecretSharing {
                threshold,
                share_count,
            },
            party_id - 1,
            &givers_pid_vec,
        );
        w_i_inner = lambda_inner * &shared_keys.x_i.0;
        w_i_outer = lambda_outer * &shared_keys.x_i.1;
    }

    println!("Creating party keys...");
    let mut party_keys_wi =
        Keys::create_from_with_safe_prime((w_i_inner.clone(), w_i_outer.clone()), my_id);
    let (com_i, decom_i) = party_keys_wi.phase1_com_decom();

    // #region Round: send commitment to g_w_i
    messenger.send_broadcast(my_id, round, &obj_to_json(&com_i)?)?;
    let round_com_ans_vec = messenger.recv_broadcasts(my_id, parties, round);
    println!("Finished reshare round: commitments collection");
    round += 1;
    // #endregion

    // #region Round: send decommitment to g_w_i
    let mut com_vec: Vec<KeyGenBroadcastMessage1> = round_com_ans_vec
        .iter()
        .map(|text| json_to_obj(text))
        .collect::<Result<Vec<_>, _>>()?;
    com_vec.insert(my_id as usize - 1, com_i);
    messenger.send_broadcast(my_id, round, &obj_to_json(&decom_i)?)?;
    let round_decom_ans_vec = messenger.recv_broadcasts(0u16, parties, round);
    println!("Finished reshare round: decommitments collection");
    round += 1;
    // #endregion

    // #region Construct aes keys
    // len PARTIES, ordered by PARTY_NUM_INT (my_id)
    let mut point_vec_inner: Vec<Point<Secp256k1>> = Vec::new();
    let mut point_vec_outer: Vec<Point<Secp256k1>> = Vec::new();
    let mut decom_vec: Vec<KeyGenDecommitMessage1> = Vec::new();
    let mut enc_keys: Vec<BigInt> = Vec::new();
    for x in round_decom_ans_vec.iter() {
        let decom_j: KeyGenDecommitMessage1 = json_to_obj(&x)?;
        point_vec_inner.push(decom_j.y_i.0.clone());
        point_vec_outer.push(decom_j.y_i.1.clone());
        decom_vec.push(decom_j.clone());
        enc_keys.push(
            (sum_tuple(&decom_j.y_i) * sum_tuple(&party_keys_wi.u_i))
                .x_coord()
                .unwrap(),
        );
    }

    let y_sum: Point<Secp256k1> = givers_vec
        .iter()
        .fold(Point::<Secp256k1>::zero(), |acc, x| {
            acc + point_vec_inner[*x as usize - 1].clone()
                + point_vec_outer[*x as usize - 1].clone()
        });
    let y_sum_bytes_big = y_sum.to_bytes(true).deref().to_vec();

    if if_give {
        if y_sum.x_coord() != keystore.unwrap().y_sum.x_coord()
            || y_sum.y_coord() != keystore.unwrap().y_sum.y_coord()
        {
            throw!(
                name = InvalidSecretKey,
                ctx = "Computed public key doesn't match keystores."
            );
        }
    }
    // #endregion

    // #region Round: set up and send range proofs
    println!("Setting up for range proofs...");
    let mut range_proof_setup = ZkpSetup::random(DEFAULT_GROUP_ORDER_BIT_LENGTH);
    let mut range_proof_public_setup = ZkpPublicSetup::from_private_zkp_setup(&range_proof_setup);
    while !(range_proof_public_setup.verify().is_ok()) {
        range_proof_setup = ZkpSetup::random(DEFAULT_GROUP_ORDER_BIT_LENGTH);
        range_proof_public_setup = ZkpPublicSetup::from_private_zkp_setup(&range_proof_setup);
    }

    messenger.send_broadcast(my_id, round, &obj_to_json(&range_proof_public_setup)?)?;
    let round_rgpsetup_ans_vec = messenger.recv_broadcasts(0u16, parties, round);
    println!("Finished reshare round: range proof setups collection");
    round += 1;
    // #endregion

    // #region Validate range proof setups
    let range_proof_public_setup_vec: Vec<ZkpPublicSetup> = round_rgpsetup_ans_vec
        .iter()
        .map(|text| json_to_obj(text))
        .collect::<Result<Vec<ZkpPublicSetup>, _>>()?;

    let correct_range_proof_public_setup_all = (0..range_proof_public_setup_vec.len())
        .all(|i| range_proof_public_setup_vec[i].verify().is_ok());
    if !correct_range_proof_public_setup_all {
        throw!(
            name = InvalidRangeProofSetup,
            ctx = &(format!(
                "Either h1 or h2 equals to 1, or dlog proof of `alpha` or `inv_alpha` is wrong"
            ) + exception_location)
        );
    }
    let dlog_statement_vec = range_proof_public_setup_vec
        .iter()
        .map(|x| DLogStatement {
            g: x.h1.clone(),
            ni: x.h2.clone(),
            N: x.N_tilde.clone(),
        })
        .collect::<Vec<DLogStatement>>(); // len of n_keygen (n_actual)
    println!("Validated range proof setups");
    // #endregion

    // #region Round: send Paillier key proofs via no-aes-p2p
    println!("Creating Paillier key proofs...");
    let plkey_proofs_send_vec = enc_keys
        .iter()
        .map(|x| {
            party_keys_wi.phase3_proof_of_correct_key(&dlog_statement_vec[my_id as usize - 1], x)
        })
        .collect::<Vec<PaillierKeyProofs>>();
    for i in 1..=parties {
        if i != my_id {
            messenger.send_p2p(
                my_id,
                i,
                round,
                &obj_to_json(&plkey_proofs_send_vec[i as usize - 1])?,
            )?;
        }
    }
    let round_plkp_ans_vec = messenger.gather_p2p(my_id, parties, round);
    println!("Finished reshare round: Paillier key proofs collection");
    round += 1;
    // #endregion

    // #region Validate paillier key proofs and create party key shares
    println!("Validating Paillier key proofs...");
    let mut paillier_proofs_rec_vec: Vec<PaillierKeyProofs> = round_plkp_ans_vec
        .iter()
        .map(|text| json_to_obj(text))
        .collect::<Result<Vec<_>, _>>()?;
    paillier_proofs_rec_vec.insert(
        my_id as usize - 1,
        plkey_proofs_send_vec[my_id as usize - 1].clone(),
    );

    let correct_key_correct_decom_all = (0..com_vec.len()).all(|i| {
        (
            HashCommitment::<Sha256>::create_commitment_with_user_defined_randomness(
                &BigInt::from_bytes(decom_vec[i].y_i.0.to_bytes(true).as_ref()),
                &decom_vec[i].blind_factor.0,
            ),
            HashCommitment::<Sha256>::create_commitment_with_user_defined_randomness(
                &BigInt::from_bytes(decom_vec[i].y_i.1.to_bytes(true).as_ref()),
                &decom_vec[i].blind_factor.1,
            ),
        ) == com_vec[i].com
            && paillier_proofs_rec_vec[i]
                .correct_key_proof
                .verify(&com_vec[i].e, zk_paillier::zkproofs::SALT_STRING)
                .is_ok()
            && paillier_proofs_rec_vec[i]
                .pblum_modulus_proof
                .verify(&com_vec[i].e.n, &enc_keys[i])
            && paillier_proofs_rec_vec[i]
                .no_small_factor_proof
                .verify(&dlog_statement_vec[i], &com_vec[i].e.n)
    });
    if !correct_key_correct_decom_all {
        throw!(
            name = InvalidSecretKey,
            ctx = &("Either invalid commitment to keyshare or invalid zkp of RSA moduli"
                .to_owned()
                + exception_location)
        );
    }
    // #endregion

    if if_give {
        let wi_inner_partition = scalar_split(&w_i_inner, &group_share_count);
        let (mut vss_scheme_inner, secret_shares_inner) =
            VerifiableSS::share(group_threshold, share_count, &w_i_inner);
        vss_scheme_inner.parameters.share_count = group_share_count;
        let secret_shares_vec_inner = this_group_receivers
            .iter()
            .map(|x| {
                let pos_rec = receivers_vec.iter().position(|y| y == x).unwrap();
                secret_shares_inner[pos_rec].clone()
            })
            .collect::<Vec<_>>();

        // #region Round: send inner shares and 1 chain code to receivers by index
        let pos_give = givers_division
            .get(&group_id)
            .unwrap()
            .iter()
            .position(|&x| x == my_id)
            .unwrap() as u16;
        for ((secret_share, wij_inner), receiver_index) in zip(
            zip(&secret_shares_vec_inner, &wi_inner_partition),
            this_group_receivers,
        ) {
            let key_i = BigInt::to_bytes(&enc_keys[*receiver_index as usize - 1]);
            let mut plaintext = BigInt::to_bytes(&secret_share.to_bigint());
            let aead_pack_i1 = aes::aes_encrypt(&key_i, &plaintext)?;
            plaintext = BigInt::to_bytes(&wij_inner.to_bigint());
            let aead_pack_i2 = aes::aes_encrypt(&key_i, &plaintext)?;
            messenger.send_p2p(
                &pos_give + 1,
                *receiver_index,
                &round * 10 + &group_id,
                &obj_to_json(&(aead_pack_i1, aead_pack_i2))?,
            )?;
        }
        println!("Finished reshare round: party key inner shares sent");
        // #endregion

        // #region Round: send outer shares to receivers
        let wi_outer_partition = scalar_split(&w_i_outer, &share_count);
        let (vss_scheme_outer, secret_shares_outer) =
            VerifiableSS::share(threshold, share_count, &w_i_outer);
        let secret_shares_vec_outer = secret_shares_outer.to_vec();
        let pos_give = givers_vec.iter().position(|&x| x == my_id).unwrap() as u16;
        for ((secret_share, wij_outer), receiver_index) in zip(
            zip(&secret_shares_vec_outer, &wi_outer_partition),
            &receivers_vec,
        ) {
            let key_i = BigInt::to_bytes(&enc_keys[*receiver_index as usize - 1]);
            let mut plaintext = BigInt::to_bytes(&secret_share.to_bigint());
            let aead_pack_i1 = aes::aes_encrypt(&key_i, &plaintext)?;
            plaintext = BigInt::to_bytes(&wij_outer.to_bigint());
            let aead_pack_i2 = aes::aes_encrypt(&key_i, &plaintext)?;
            messenger.send_p2p(
                &pos_give + 1,
                *receiver_index,
                round,
                &obj_to_json(&(aead_pack_i1, aead_pack_i2))?,
            )?;
        }
        println!("Finished reshare round: party key outer shares sent");
        // #endregion

        // #region Round: broadcast vss_scheme_vec
        let pos_give = givers_vec.iter().position(|&x| x == my_id).unwrap() as u16;
        messenger.send_broadcast(
            &pos_give + 1,
            &round + 1,
            &obj_to_json(&(&vss_scheme_inner, &vss_scheme_outer))?,
        )?;
        println!("Finished reshare round: VSS commitments sent");
        // #endregion
    }

    if if_receive {
        // #region Round: collect party key inner shares
        let round_share_ans_vec_inner = messenger.gather_p2p_all(
            my_id,
            this_group_givers.len() as u16,
            &round * 10 + &group_id,
        );
        let mut party_shares_inner: Vec<Scalar<Secp256k1>> = Vec::new();
        let mut w_ji_inner_vec: Vec<Scalar<Secp256k1>> = Vec::new();

        for (round_ans, giver_index) in zip(&round_share_ans_vec_inner, this_group_givers) {
            let (aead_pack_i1, aead_pack_i2): (aes::AEAD, aes::AEAD) = json_to_obj(round_ans)?;
            let key_i = BigInt::to_bytes(&enc_keys[*giver_index as usize - 1]);

            let mut out = aes::aes_decrypt(&key_i, &aead_pack_i1)?;
            let mut out_bn = BigInt::from_bytes(&out);
            let mut out_fe = Scalar::<Secp256k1>::from(&out_bn);
            party_shares_inner.push(out_fe);

            out = aes::aes_decrypt(&key_i, &aead_pack_i2)?;
            out_bn = BigInt::from_bytes(&out);
            out_fe = Scalar::<Secp256k1>::from(&out_bn);
            w_ji_inner_vec.push(out_fe);
        }
        println!("Finished reshare round: party key inner shares received");
        // #endregion

        // #region Round: collect party key outer shares
        let round_share_ans_vec_outer = messenger.gather_p2p_all(my_id, givers, round);
        let mut party_shares_outer: Vec<Scalar<Secp256k1>> = Vec::new();
        let mut w_ji_outer_vec: Vec<Scalar<Secp256k1>> = Vec::new();

        for (round_ans, giver_index) in zip(&round_share_ans_vec_outer, &givers_vec) {
            let (aead_pack_i1, aead_pack_i2): (aes::AEAD, aes::AEAD) = json_to_obj(round_ans)?;
            let key_i = BigInt::to_bytes(&enc_keys[*giver_index as usize - 1]);

            let mut out = aes::aes_decrypt(&key_i, &aead_pack_i1)?;
            let mut out_bn = BigInt::from_bytes(&out);
            let mut out_fe = Scalar::<Secp256k1>::from(&out_bn);
            party_shares_outer.push(out_fe);

            out = aes::aes_decrypt(&key_i, &aead_pack_i2)?;
            out_bn = BigInt::from_bytes(&out);
            out_fe = Scalar::<Secp256k1>::from(&out_bn);
            w_ji_outer_vec.push(out_fe);
        }
        println!("Finished reshare round: party key outer shares received");
        // #endregion

        // #region Round: collect VSS commitments
        let round_vss_ans_vec = messenger.recv_broadcasts(0u16, givers, &round + 1);
        round += 2;
        println!("Finished reshare round: VSS commitments received");
        // #endregion

        // #region Reconstruct VSS commitment vector
        let mut vss_vec_inner: Vec<VerifiableSS<Secp256k1>> = Vec::new();
        let mut vss_vec_outer: Vec<VerifiableSS<Secp256k1>> = Vec::new();
        for i in 0..givers as usize {
            let (vss_inner, vss_outer): (VerifiableSS<Secp256k1>, VerifiableSS<Secp256k1>) =
                json_to_obj(&round_vss_ans_vec[i])?;
            vss_vec_inner.push(vss_inner);
            vss_vec_outer.push(vss_outer);
        }
        let mut vss_vec_inner_full: Vec<VerifiableSS<Secp256k1>> =
            vec![vss_scheme_zero.clone(); share_count as usize];
        let mut vss_vec_outer_full: Vec<VerifiableSS<Secp256k1>> =
            vec![vss_scheme_zero.clone(); share_count as usize];
        let mut vss_division: HashMap<
            u16,
            Vec<(VerifiableSS<Secp256k1>, VerifiableSS<Secp256k1>)>,
        > = HashMap::new();
        for id in givers_group_id.iter() {
            let one_group_vss = givers_division
                .get(id)
                .unwrap()
                .iter()
                .map(|m| {
                    (
                        vss_vec_inner[givers_vec.iter().position(|&x| x == *m).unwrap()].clone(),
                        vss_vec_outer[givers_vec.iter().position(|&x| x == *m).unwrap()].clone(),
                    )
                })
                .collect::<Vec<(_, _)>>();
            vss_division.insert(*id, one_group_vss);
        }
        for id in receivers_group_id.iter() {
            let one_group_receiver = receivers_division.get(id).unwrap();
            let one_group_giver = givers_division.get(id).unwrap();
            let one_group_vss = vss_division.get(id).unwrap();
            let receiver_gt = one_group_vss[0].0.parameters.threshold;
            let receiver_gn = one_group_vss[0].0.parameters.share_count;
            for index in 0..one_group_receiver.len() {
                let pos_vss = receivers_vec
                    .iter()
                    .position(|&x| x == one_group_receiver[index])
                    .unwrap();
                if index < one_group_giver.len() {
                    (vss_vec_inner_full[pos_vss], vss_vec_outer_full[pos_vss]) =
                        one_group_vss[index].clone();
                } else {
                    vss_vec_inner_full[pos_vss] = VerifiableSS::<Secp256k1> {
                        parameters: ShamirSecretSharing {
                            threshold: receiver_gt,
                            share_count: receiver_gn,
                        },
                        commitments: vec![
                            Point::<Secp256k1>::zero();
                            one_group_vss[0].0.parameters.threshold as usize + 1
                        ],
                    };
                    vss_vec_outer_full[pos_vss] = VerifiableSS::<Secp256k1> {
                        parameters: ShamirSecretSharing {
                            threshold,
                            share_count,
                        },
                        commitments: vec![Point::<Secp256k1>::zero(); threshold as usize + 1],
                    };
                }
            }
        }
        println!("Finished VSS commitments reordered");
        // #endregion

        // #region Validate polynomial evaluation
        let pos_rec = receivers_vec.iter().position(|&x| x == my_id).unwrap() as u16;
        let this_group_vss = vss_division.get(&group_id).unwrap();
        let correct_ss_verify_inner = (0..party_shares_inner.len()).all(|i| {
            this_group_vss[i]
                .0
                .validate_share(&party_shares_inner[i], &pos_rec + 1)
                .is_ok()
        });
        let correct_ss_verify_outer = (0..party_shares_outer.len()).all(|i| {
            vss_vec_outer[i]
                .validate_share(&party_shares_outer[i], &pos_rec + 1)
                .is_ok()
        });

        if !(correct_ss_verify_inner && correct_ss_verify_outer) {
            throw!(
                name = InvalidSecretKey,
                ctx = &("Invalid verifiable secret sharing".to_owned() + exception_location)
            );
        }

        shared_keys.x_i = (
            party_shares_inner.iter().sum(),
            party_shares_outer.iter().sum(),
        );
        shared_keys.y = y_sum.clone();
        // #endregion

        // #region Round: send dlog proof of x_i by Schnorr identification protocol
        let dlog_proof: (DLogProof<Secp256k1, Sha256>, DLogProof<Secp256k1, Sha256>) = (
            DLogProof::prove(&shared_keys.x_i.0),
            DLogProof::prove(&shared_keys.x_i.1),
        );

        messenger.send_broadcast(&pos_rec + 1, round, &obj_to_json(&dlog_proof)?)?;
        let round_dlog_ans_vec = messenger.recv_broadcasts(0u16, share_count, round);
        round += 1;
        println!("Finished reshare round: PoK of `x_i` collection");
        // #endregion

        // #region Verify dlog proof
        let dlog_proof_vec = round_dlog_ans_vec
            .iter()
            .map(|m| json_to_obj(m))
            .collect::<Result<Vec<(DLogProof<Secp256k1, Sha256>, DLogProof<Secp256k1, Sha256>)>, _>>()?;
        let xi_dlog_verify_inner =
            (0..share_count as usize).all(|i| DLogProof::verify(&dlog_proof_vec[i].0).is_ok());
        let xi_dlog_verify_outer =
            (0..share_count as usize).all(|i| DLogProof::verify(&dlog_proof_vec[i].1).is_ok());

        if !(xi_dlog_verify_inner && xi_dlog_verify_outer) {
            throw!(
                name = DlogProofFailed,
                ctx = &("Bad dlog proof of `x_i`".to_owned() + exception_location)
            )
        }
        println!("Verified PoK of `x_i`!");
        // #endregion

        // #region Round: broadcast ACK with chain code
        let y_sum_bytes_small = y_sum.to_bytes(false).deref().to_vec();
        let chain_code: ChainCode = match Sha512::digest(&y_sum_bytes_small).get(..32) {
            Some(arr) => arr.try_into().unwrap(),
            None => {
                throw!(
                    name = ChildKeyDerivationFailed,
                    ctx = &(format!(
                        "Bad Sha512 digest for ChainCode, input_bytes_hex={}",
                        hex::encode(&y_sum_bytes_small)
                    ) + exception_location)
                )
            }
        };
        messenger.send_broadcast(
            &pos_rec + 1,
            round,
            &obj_to_json(&("ack".as_bytes().to_owned().append(&mut chain_code.to_vec())))?,
        )?;
        let round_ack_ans_vec = messenger.recv_broadcasts(0u16, share_count, round);
        if !&round_ack_ans_vec.windows(2).all(|w| w[0] == w[1]) {
            throw!(
                name = InvalidACK,
                ctx = &(format!("Error unexpected occured")
                    + exception_location
                    + "All should stop writing into keystores.")
            )
        }
        println!("Finished reshare round: acknowledgment collection");
        // #endregion

        // #region Compose keystore json
        party_keys_wi.u_i = (w_ji_inner_vec.iter().sum(), w_ji_outer_vec.iter().sum());
        party_keys_wi.y_i = (
            &party_keys_wi.u_i.0 * Point::<Secp256k1>::generator(),
            &party_keys_wi.u_i.1 * Point::<Secp256k1>::generator(),
        );
        party_keys_wi.party_index = &pos_rec + 1;
        let paillier_key_vec = receivers_vec
            .iter()
            .map(|x| com_vec[*x as usize - 1].e.clone())
            .collect::<Vec<EncryptionKey>>();

        let mnemonic =
            Mnemonic::from_entropy(&sum_tuple(&party_keys_wi.u_i).to_bytes(), Language::English)
                .catch_anyhow(
                    InvalidSecretKey,
                    &("Cannot create mnemonic".to_owned() + exception_location),
                )?; // TODO: consider 2 mnemonics?
        let phrase: String = mnemonic.phrase().to_string();

        let keystore = KeyStore {
            party_keys: party_keys_wi,
            shared_keys,
            party_id: &pos_rec + 1,
            vss_scheme_vec: (vss_vec_inner_full, vss_vec_outer_full),
            paillier_key_vec,
            y_sum,
            chain_code,
            group_id,
            group_division,
            dlog_statement_vec,
        };
        // #endregion

        // #region Round: terminate
        let pk_hex_compressed = hex::encode(&y_sum_bytes_big);
        messenger.send_broadcast(&pos_rec + 1, round, &pk_hex_compressed)?;
        // #endregion

        println!("Finished reshare");
        Ok((phrase, keystore))
    } else {
        println!("Finished reshare");
        Ok((
            "Non-receivers have neither mnemonic phrase nor write access to keysfiles".to_string(),
            keystore.unwrap().clone(),
        ))
    }
}

fn sum_tuple<T: std::ops::Add<Output = T> + Clone>(tuple: &(T, T)) -> T {
    tuple.0.clone() + tuple.1.clone()
}
