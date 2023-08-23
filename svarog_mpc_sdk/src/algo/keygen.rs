//! This is a modified version of `gg18_keygen_client.rs` of Kzen Networks' implementation of GG18 key generation:
//! https://github.com/ZenGo-X/multi-party-ecdsa/blob/master/examples/gg18_keygen_client.rs
//!

use std::ops::Deref;

use bip32::ChainCode; // chain_code = left half of SHA512(pk)
use bip32::{ChildNumber, ExtendedKey, ExtendedKeyAttrs, Prefix};
use bip39::{Language, Mnemonic};
use curv::{
    arithmetic::traits::Converter,
    cryptographic_primitives::{
        proofs::sigma_dlog::DLogProof, secret_sharing::feldman_vss::VerifiableSS,
    },
    elliptic::curves::{secp256_k1::Secp256k1, Point, Scalar},
    BigInt,
};
use multi_party_ecdsa::protocols::multi_party_ecdsa::gg_2018::party_i::{
    self as kzen, KeyGenBroadcastMessage1, KeyGenDecommitMessage1, Keys as GG18Keys,
    SharedKeys as GG18SharedKeys,
};
use paillier::EncryptionKey;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256, Sha512};
use xuanmi_base_support::*;

use super::aes;
use super::{aes_decrypt, aes_encrypt, SparseArray, ToVecByKeyOrder, AEAD};
use crate::protogen::server::SessionConfig;

#[tracing::instrument()]
pub async fn algo_keygen() -> Outcome<KeyStore> {
    // find my id
    
}

pub fn algo_keygen2(server: &str, tr_uuid: &str, tn_config: &[u16; 5]) -> Outcome<KeygenT> {
    let (threshold, n_keygen, n_actual, group_threshold, group_sharecount, group_id) = (
        tn_config[0],
        tn_config[1],
        tn_config[1],
        tn_config[2],
        tn_config[3],
        tn_config[4],
    );
    if threshold >= n_keygen || group_threshold >= group_sharecount {
        throw!(
            name = InvalidConfigs,
            ctx = &format!(
                "t/n config and group config should satisfy t<n.\n\tHowever, {}/{} and {}/{} were provided",
                threshold, n_keygen, group_threshold, group_sharecount,
            )
        );
    }

    let mut round: u16 = 0;
    println!(
        "Start keygen with \n\tthreshold={}, n_keygen={}, \n\tgroup_threshold={}, group_sharecount={}, group_id={}",
        threshold, n_keygen, group_threshold, group_sharecount, group_id,
    );
    let messenger =
        MpcClientMessenger::signup(server, "keygen", tr_uuid, threshold, n_actual, n_keygen)
            .catch(
                SignUpFailed,
                &format!(
                    "Cannot sign up for key geneation with server={}, tr_uuid={}.",
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

    let config = kzen::Parameters {
        threshold,
        share_count: n_keygen,
    };
    let group_config = kzen::Parameters {
        threshold: group_threshold,
        share_count: group_sharecount,
    };

    // #region Round: collect information
    messenger.send_broadcast(
        my_id,
        round,
        &obj_to_json(&(my_id, group_threshold, group_sharecount, group_id))?,
    )?;
    let round_info_ans_vec = messenger.recv_broadcasts(0u16, n_actual, round);
    println!("Finished keygen round: info collection");
    round += 1;
    // #endregion

    // #region Parse and validate information
    let keygen_info_vec: Vec<(u16, u16, u16, u16)> = round_info_ans_vec
        .iter()
        .map(|text| json_to_obj(text))
        .collect::<Result<Vec<(u16, u16, u16, u16)>, _>>()?;
    let mut group_id_list = keygen_info_vec.iter().map(|x| x.3).collect::<Vec<_>>();
    group_id_list.sort();
    group_id_list.dedup();
    let group_division = keygen_info_vec.iter().fold(HashMap::new(), |mut acc, x| {
        acc.entry(x.3).or_insert_with(Vec::new).push(x.0 - 1);
        acc
    });

    let this_group = group_division.get(&group_id).cloned().unwrap_or_default();
    if this_group.len() != group_sharecount as usize {
        throw!(
            name = InvalidConfigs,
            ctx = &(format!(
                "Len={} of group (group_id={}) contradicts group_sharecount ({})",
                this_group.len(),
                group_id,
                group_sharecount,
            ) + exception_location)
        );
    }

    if let Some(x) = keygen_info_vec
        .iter()
        .find(|x| x.3 == group_id && (x.1 != group_threshold || x.2 != group_sharecount))
    {
        throw!(
            name = InvalidConfigs,
            ctx = &(format!("Group parameters don't match at Party {}", x.0 + 1)
                + exception_location)
        );
    }

    let pos_in_this_group = this_group.iter().position(|&e| e == my_id - 1).if_none(
        InvalidConfigs,
        &(format!("Element ({}) not found in this group", my_id - 1) + exception_location),
    )?;
    // #endregion

    // #region Create party keys
    println!("Creating party keys...");
    let party_keys = kzen::Keys::create_with_safe_prime(my_id); // instead of kzen::Keys::create(my_id)
    let mnemonic =
        Mnemonic::from_entropy(&sum_tuple(&party_keys.u_i).to_bytes(), Language::English)
            .catch_anyhow(
                InvalidSecretKey,
                &("Cannot create mnemonic".to_owned() + exception_location),
            )?; // TODO: consider 2 mnemonics?
    let phrase: String = mnemonic.phrase().to_string();
    // #endregion

    // #region Round: send commitment to ephemeral public keys
    let (bc_i, decom_i) = party_keys.phase1_com_decom();
    messenger.send_broadcast(my_id, round, &obj_to_json(&bc_i)?)?;
    let round_com_ans_vec = messenger.recv_broadcasts(0u16, n_actual, round);
    println!("Finished keygen round: commitments collection");
    round += 1;
    // #endregion

    // #region Round: send decommitment to ephemeral public keys
    let bc1_vec: Vec<KeyGenBroadcastMessage1> = round_com_ans_vec
        .iter()
        .map(|text| json_to_obj(text))
        .collect::<Result<Vec<_>, _>>()?;
    messenger.send_broadcast(my_id, round, &obj_to_json(&decom_i)?)?;
    let round_decom_ans_vec = messenger.recv_broadcasts(0u16, n_actual, round);
    println!("Finished keygen round: decommitments collection");
    round += 1;
    // #endregion

    // #region Construct aes keys
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
            (sum_tuple(&decom_j.y_i) * sum_tuple(&party_keys.u_i))
                .x_coord()
                .unwrap(),
        );
    }

    let (head, tail) = point_vec_inner.split_at(1);
    let (head_prime, tail_prime) = point_vec_outer.split_at(1);
    let y_sum = tail.iter().fold(head[0].clone(), |acc, x| acc + x)
        + tail_prime
            .iter()
            .fold(head_prime[0].clone(), |acc, x| acc + x);
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
    let round_rgpsetup_ans_vec = messenger.recv_broadcasts(0u16, n_actual, round);
    println!("Finished keygen round: range proof setups collection");
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
        .map(|x| party_keys.phase3_proof_of_correct_key(&dlog_statement_vec[my_id as usize - 1], x))
        .collect::<Vec<PaillierKeyProofs>>();
    for i in 1..=n_actual {
        if i != my_id {
            messenger.send_p2p(
                my_id,
                i,
                round,
                &obj_to_json(&plkey_proofs_send_vec[i as usize - 1])?,
            )?;
        }
    }
    let round_plkp_ans_vec = messenger.gather_p2p(my_id, n_actual, round);
    println!("Finished keygen round: Paillier key proofs collection");
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

    let (
        (mut vss_scheme_inner, vss_scheme_outer),
        (secret_shares_inner, secret_shares_outer),
        _index,
    ) = {
        match party_keys.phase1_verify_com_phase3_verify_correct_key_phase2_distribute(
            &(kzen::Parameters {
                threshold: group_threshold,
                share_count: n_keygen,
            }, config.clone()),
            &decom_vec,
            &bc1_vec,
            &paillier_proofs_rec_vec,
            &enc_keys,
            &dlog_statement_vec,
        ) {
            Ok(_ok) => _ok,
            Err(_) => throw!(
                name = InvalidSecretKey,
                ctx = &("Either invalid commitment to keyshare in `Phase1` or invalid zkp of RSA moduli in `Phase3`"
                    .to_owned()
                    + exception_location)
            ),
        }
    };
    vss_scheme_inner.parameters.share_count = group_sharecount;
    println!("Validated Paillier key proofs. Created party key shares");
    // #endregion

    // #region Round: send party key shares via aes-p2p
    for i in 0..group_sharecount as usize {
        if this_group[i] != my_id - 1 {
            // prepare encrypted share for party i
            let key_i = BigInt::to_bytes(&enc_keys[this_group[i] as usize]);
            let plaintext =
                BigInt::to_bytes(&secret_shares_inner[this_group[i] as usize].to_bigint());
            let aead_pack_i = aes::aes_encrypt(&key_i, &plaintext)?;
            messenger.send_p2p(
                pos_in_this_group as u16 + 1,
                i as u16 + 1,
                &round * 10 + &group_id,
                &obj_to_json(&aead_pack_i)?,
            )?;
        }
    }

    for i in 0..n_actual {
        if i != my_id - 1 {
            // prepare encrypted share for party i
            let key_i = BigInt::to_bytes(&enc_keys[i as usize]);
            let plaintext = BigInt::to_bytes(&secret_shares_outer[i as usize].to_bigint());
            let aead_pack_i = aes::aes_encrypt(&key_i, &plaintext)?;
            messenger.send_p2p(my_id, i + 1, round, &obj_to_json(&aead_pack_i)?)?;
        }
    }

    let round_share_ans_vec_inner = messenger.gather_p2p(
        pos_in_this_group as u16 + 1,
        group_sharecount,
        &round * 10 + &group_id,
    );
    let round_share_ans_vec_outer = messenger.gather_p2p(my_id, n_actual, round);
    println!("Finished keygen round: party key shares exchange");
    round += 1;
    // #endregion

    // #region Round: send VSS commitments
    let mut j = 0;
    let mut party_shares_inner: Vec<Scalar<Secp256k1>> = Vec::new();
    for i in 0..group_sharecount as usize {
        if this_group[i] == my_id - 1 {
            party_shares_inner.push(secret_shares_inner[my_id as usize - 1].clone());
        } else {
            let aead_pack: aes::AEAD = json_to_obj(&round_share_ans_vec_inner[j])?;
            let key_i = BigInt::to_bytes(&enc_keys[this_group[i] as usize]);
            let out = aes::aes_decrypt(&key_i, &aead_pack)?;
            let out_bn = BigInt::from_bytes(&out);
            let out_fe = Scalar::<Secp256k1>::from(&out_bn);
            party_shares_inner.push(out_fe);
            j += 1;
        }
    }
    j = 0;
    let mut party_shares_outer: Vec<Scalar<Secp256k1>> = Vec::new();
    for i in 0..n_actual {
        if i == my_id - 1 {
            party_shares_outer.push(secret_shares_outer[my_id as usize - 1].clone());
        } else {
            let aead_pack: aes::AEAD = json_to_obj(&round_share_ans_vec_outer[j])?;
            let key_i = BigInt::to_bytes(&enc_keys[i as usize]);
            let out = aes::aes_decrypt(&key_i, &aead_pack)?;
            let out_bn = BigInt::from_bytes(&out);
            let out_fe = Scalar::<Secp256k1>::from(&out_bn);
            party_shares_outer.push(out_fe);
            j += 1;
        }
    }

    messenger.send_broadcast(
        my_id,
        round,
        &obj_to_json(&(&vss_scheme_inner, &vss_scheme_outer))?,
    )?;
    let round_vss_com_ans_vec = messenger.recv_broadcasts(my_id, n_actual, round);
    println!("Finished keygen round: VSS commitments collection");
    round += 1;
    // #endregion

    // #region Round: send dlog proof
    let mut j = 0;
    let mut vss_scheme_vec_inner: Vec<VerifiableSS<Secp256k1>> = Vec::new();
    let mut vss_scheme_vec_outer: Vec<VerifiableSS<Secp256k1>> = Vec::new();
    for i in 1..=n_keygen {
        let (vss_inner, vss_outer) = if i == my_id {
            (vss_scheme_inner.clone(), vss_scheme_outer.clone())
        } else {
            let vss_scheme_j: (VerifiableSS<Secp256k1>, VerifiableSS<Secp256k1>) =
                json_to_obj(&round_vss_com_ans_vec[j])?;
            j += 1;
            vss_scheme_j
        };
        vss_scheme_vec_inner.push(vss_inner);
        vss_scheme_vec_outer.push(vss_outer);
    }

    let (mut shared_keys, dlog_proof) = {
        match party_keys.phase2_verify_vss_construct_keypair_phase3_pok_dlog(
            (&group_config, &config),
            (
                &this_group
                    .iter()
                    .map(|&i| point_vec_inner[i as usize].clone())
                    .collect::<Vec<_>>(),
                &point_vec_outer,
            ),
            (&party_shares_inner, &party_shares_outer),
            (
                &this_group
                    .iter()
                    .map(|&i| vss_scheme_vec_inner[i as usize].clone())
                    .collect::<Vec<_>>(),
                &vss_scheme_vec_outer,
            ),
            my_id,
        ) {
            Ok(_ok) => _ok,
            Err(__) => throw!(
                name = InvalidSecretKey,
                ctx = &("Invalid verifiable secret sharing in `Phase2`".to_owned()
                    + exception_location)
            ),
        }
    };
    shared_keys.y = y_sum.clone();

    messenger.send_broadcast(my_id, round, &obj_to_json(&dlog_proof)?)?;
    let round_xi_ans_vec = messenger.recv_broadcasts(my_id, n_actual, round);
    println!("Finished keygen round: PoK of `x_i` collection");
    round += 1;
    // #endregion

    // #region Verify dlog proof
    let mut j = 0;
    let mut dlog_proof_vec: Vec<(DLogProof<Secp256k1, Sha256>, DLogProof<Secp256k1, Sha256>)> =
        Vec::new();
    for i in 1..=n_keygen {
        if i == my_id {
            dlog_proof_vec.push(dlog_proof.clone());
        } else {
            let dlog_proof_j = json_to_obj(&round_xi_ans_vec[j])?;
            dlog_proof_vec.push(dlog_proof_j);
            j += 1;
        }
    }

    match kzen::Keys::verify_dlog_proofs(
        &config,
        &dlog_proof_vec,
        (&point_vec_inner, &point_vec_outer),
    ) {
        Ok(_) => {}
        Err(_) => throw!(
            name = DlogProofFailed,
            ctx = &("Bad dlog proof of `x_i` in `Phase3`".to_owned() + exception_location)
        ),
    }
    println!("Verified PoK of `x_i`!");
    // #endregion

    // #region Compose keystore json
    let paillier_key_vec = (0..n_keygen)
        .map(|i| bc1_vec[i as usize].e.clone())
        .collect::<Vec<EncryptionKey>>();
    let y_sum_bytes_small = y_sum.to_bytes(false).deref().to_vec();
    let y_sum_bytes_big = y_sum.to_bytes(true).deref().to_vec();
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
    let keystore = KeyStore {
        party_keys,
        shared_keys,
        party_id: my_id,
        vss_scheme_vec: (vss_scheme_vec_inner, vss_scheme_vec_outer),
        paillier_key_vec,
        y_sum: y_sum.clone(),
        chain_code,
        group_id,
        group_division,
        dlog_statement_vec,
    };
    // #endregion

    // #region Round: terminate
    let pk_hex_compressed = hex::encode(&y_sum_bytes_big);
    messenger.send_broadcast(my_id, round, &pk_hex_compressed)?;
    println!("Finished keygen");
    // #endregion

    Ok((phrase, keystore))
}

fn sum_tuple<T: std::ops::Add<Output = T> + Clone>(tuple: &(T, T)) -> T {
    tuple.0.clone() + tuple.1.clone()
}
