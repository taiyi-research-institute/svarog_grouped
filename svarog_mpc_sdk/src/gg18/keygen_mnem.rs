//! This is a modified version of `gg18_keygen_client.rs` of Kzen Networks' implementation of GG18 key generation:
//! https://github.com/ZenGo-X/multi-party-ecdsa/blob/master/examples/gg18_keygen_client.rs
//!

use bip32::ChainCode; // chain_code = left half of SHA512(pk)
use bip39::{Language, Mnemonic, Seed};
use bitcoin::util::bip32::ExtendedPrivKey;
use bitcoin::Network;
use curv::{
    arithmetic::traits::Converter,
    cryptographic_primitives::{
        proofs::sigma_dlog::DLogProof, secret_sharing::feldman_vss::VerifiableSS,
    },
    elliptic::curves::{secp256_k1::Secp256k1, Point, Scalar},
};
use sha2::{Sha256, Sha512};
use tonic::async_trait;
use xuanmi_base_support::*;
use zk_paillier::zkproofs::DLogStatement;

use super::*;
use crate::mpc_member::*;
use crate::{mta::range_proofs::*, util::*};

#[async_trait]
pub trait AlgoKeygenMnem {
    async fn algo_keygen_mnem(&mut self, mnem: &str, pwd: &str) -> Outcome<KeyStore>;
}

#[async_trait]
impl AlgoKeygenMnem for MpcMember {
    async fn algo_keygen_mnem(&mut self, mnem: &str, pwd: &str) -> Outcome<KeyStore> {
        let my_id = self.member_id;
        let my_group_id = self.group_id;
        let key_mates = self.member_attending.clone();
        let group_mates = self.group_member[&self.group_id].clone();
        let key_mates_wome = {
            let mut _km = key_mates.clone();
            _km.remove(&my_id);
            _km
        };
        let group_mates_wome = {
            let mut _gm = group_mates.clone();
            _gm.remove(&my_id);
            _gm
        };
        let config = Parameters {
            threshold: (self.key_quorum - 1) as u16,
            share_count: key_mates.len() as u16,
        };
        let group_config = Parameters {
            threshold: (self.group_quora[&my_group_id] - 1) as u16,
            share_count: group_mates.len() as u16,
        };
        let mnem_provider_id = self.mnem_provider_id;

        let mut party_keys = Keys::create_with_safe_prime(self.member_id as u16); // instead of kzen::Keys::create(my_id)
        let mut expected_y_sum = Point::<Secp256k1>::generator().to_point();

        let mut purpose = "pre commitment";
        let (mut com_i, mut decom_i) = party_keys.phase1_com_decom();
        self.postmsg_mcast(key_mates.iter(), purpose, &com_i)
            .await
            .catch_()?;
        let com_vec: SparseVec<KeyGenBroadcastMessage1> = self
            .getmsg_mcast(key_mates.iter(), purpose)
            .await
            .catch_()?;

        purpose = "pre decommitment";
        self.postmsg_mcast(key_mates.iter(), purpose, &decom_i)
            .await
            .catch_()?;
        let decom_vec: SparseVec<KeyGenDecommitMessage1> = self
            .getmsg_mcast(key_mates.iter(), purpose)
            .await
            .catch_()?;

        let enc_keys = {
            let mut enc_keys = SparseVec::with_capacity(16);
            for (id, decom) in decom_vec.iter() {
                let enc_key =
                    (&decom.y_i.0 + &decom.y_i.1) * (&party_keys.u_i.0 + &party_keys.u_i.1);
                let enc_key = enc_key.x_coord().unwrap();
                enc_keys.insert(*id, enc_key);
            }
            enc_keys
        };

        // TODO: validate decom correctness

        purpose = "pre distribute party_key";
        let chain_code = if !mnem.is_empty() {
            let seed = Seed::new(
                &Mnemonic::from_phrase(mnem, Language::English).catch_()?,
                pwd,
            );
            let seed_bytes: &[u8] = seed.as_bytes();
            let master_sk = ExtendedPrivKey::new_master(Network::Bitcoin, seed_bytes).catch_()?;
            expected_y_sum =
                &Scalar::<Secp256k1>::from_bytes(&master_sk.private_key.secret_bytes()).catch_()?
                    * Point::<Secp256k1>::generator();
            let chain_code = master_sk.chain_code.to_bytes();
            let partition = scalar_split_inner_outer(
                &Scalar::<Secp256k1>::from_bytes(&master_sk.private_key.secret_bytes()).catch_()?,
                key_mates.iter().cloned().collect(),
            );
            // preround 3: send secret shares via aes-p2p
            for (id, (part_inner, part_outer)) in &partition {
                if *id == my_id {
                    continue;
                }
                let key = enc_keys.get(id).ifnone_()?.to_bytes();
                let mut enc_inner = part_inner.to_bytes().as_ref().to_vec();
                let aead_inner = aes_encrypt(&key, &enc_inner).catch_()?;
                let mut enc_outer = part_outer.to_bytes().as_ref().to_vec();
                let aead_outer = aes_encrypt(&key, &enc_outer).catch_()?;
                let aead_chain_code = aes_encrypt(&key, &chain_code).catch_()?;
                self.postmsg_p2p(*id, purpose, &(aead_inner, aead_outer, aead_chain_code))
                    .await
                    .catch_()?;
            }
            party_keys.u_i.0 = partition.get(&my_id).unwrap().0.clone();
            party_keys.u_i.1 = partition.get(&my_id).unwrap().1.clone();
            party_keys.y_i.0 = &party_keys.u_i.0 * Point::<Secp256k1>::generator();
            party_keys.y_i.1 = &party_keys.u_i.1 * Point::<Secp256k1>::generator();
            chain_code
        } else {
            let aeads: SparseVec<(AEAD, AEAD, AEAD)> = self
                .getmsg_mcast(key_mates.iter(), purpose)
                .await
                .catch_()?;
            let aeads = aeads.values().next().ifnone_()?.clone();
            let aead_inner = aeads.0;
            let aead_outer = aeads.1;
            let aead_chain_code = aeads.2;
            let key = enc_keys.get(&mnem_provider_id).unwrap().to_bytes();

            let inner = aes_decrypt(&key, &aead_inner).catch_()?;
            let inner = Scalar::<Secp256k1>::from_bytes(&inner).catch_()?;

            let outer = aes_decrypt(&key, &aead_outer).catch_()?;
            let outer = Scalar::<Secp256k1>::from_bytes(&outer).catch_()?;

            let chain_code = aes_decrypt(&key, &aead_chain_code).catch_()?;
            assert_throw!(chain_code.len() == 32);

            party_keys.u_i.0 = inner;
            party_keys.u_i.1 = outer;
            party_keys.y_i.0 = &party_keys.u_i.0 * Point::<Secp256k1>::generator();
            party_keys.y_i.1 = &party_keys.u_i.1 * Point::<Secp256k1>::generator();

            chain_code.try_into().unwrap()
        };

        /***** Below is identical to ordinary keygen *****/

        let mut purpose = "commitment";
        let (bc_i, decom_i) = party_keys.phase1_com_decom();
        self.postmsg_mcast(key_mates.iter(), purpose, &bc_i)
            .await
            .catch_()?;
        let com_vec: SparseVec<KeyGenBroadcastMessage1> = self
            .getmsg_mcast(key_mates.iter(), purpose)
            .await
            .catch_()?;

        purpose = "decommitment";
        self.postmsg_mcast(key_mates.iter(), purpose, &decom_i)
            .await
            .catch_()?;
        let decom_vec: SparseVec<KeyGenDecommitMessage1> = self
            .getmsg_mcast(key_mates.iter(), purpose)
            .await
            .catch_()?;
        let point_inner_vec: SparseVec<Point<Secp256k1>> = {
            let mut point_inner_vec = SparseVec::with_capacity(16);
            for (id, decom) in decom_vec.iter() {
                point_inner_vec.insert(*id, decom.y_i.0.clone());
            }
            point_inner_vec
        };
        let point_outer_vec: SparseVec<Point<Secp256k1>> = {
            let mut point_outer_vec = SparseVec::with_capacity(16);
            for (id, decom) in decom_vec.iter() {
                point_outer_vec.insert(*id, decom.y_i.1.clone());
            }
            point_outer_vec
        };
        let enc_keys = {
            let mut enc_keys = SparseVec::with_capacity(16);
            for (id, decom) in decom_vec.iter() {
                let enc_key =
                    (&decom.y_i.0 + &decom.y_i.1) * (&party_keys.u_i.0 + &party_keys.u_i.1);
                let enc_key = enc_key.x_coord().unwrap();
                enc_keys.insert(*id, enc_key);
            }
            enc_keys
        };

        let _decom_vec = decom_vec.values_sorted_by_key_asc();
        let (decom_head, decom_tail) = _decom_vec.split_at(1);
        let decom_head = &decom_head[0];
        let y_sum = decom_tail // accumulate over tails
            .iter()
            .fold(decom_head.y_i.0.clone(), |acc, x| acc + &x.y_i.0);

        // root pubkey
        let y_sum = y_sum // accumulate voer tail primes
            + decom_tail
                .iter()
                .fold(decom_head.y_i.1.clone(), |acc, x| acc + &x.y_i.1);

        purpose = "exchange range proof";
        let mut range_proof_setup = ZkpSetup::random(DEFAULT_GROUP_ORDER_BIT_LENGTH);
        let mut range_proof_public_setup =
            ZkpPublicSetup::from_private_zkp_setup(&range_proof_setup).catch_()?;
        while !(range_proof_public_setup.verify().is_ok()) {
            range_proof_setup = ZkpSetup::random(DEFAULT_GROUP_ORDER_BIT_LENGTH);
            range_proof_public_setup =
                ZkpPublicSetup::from_private_zkp_setup(&range_proof_setup).catch_()?;
        }
        self.postmsg_mcast(key_mates.iter(), purpose, &range_proof_public_setup)
            .await
            .catch_()?;
        let rgpsetup_ans_vec: SparseVec<ZkpPublicSetup> = self
            .getmsg_mcast(key_mates.iter(), purpose)
            .await
            .catch_()?;
        let range_proof_public_setup_all_correct = rgpsetup_ans_vec
            .iter()
            .all(|(_id, pubsetup)| pubsetup.verify().is_ok());
        assert_throw!(
            range_proof_public_setup_all_correct,
            "Either h1 or h2 equals to 1, or dlog proof of `alpha` or `inv_alpha` is wrong"
        );

        let dlog_stmt_vec: SparseVec<DLogStatement> = {
            let mut dlog_stmt_vec = SparseVec::with_capacity(16);
            for (id, pubsetup) in rgpsetup_ans_vec.iter() {
                let v = DLogStatement {
                    g: pubsetup.h1.clone(),
                    ni: pubsetup.h2.clone(),
                    N: pubsetup.N_tilde.clone(),
                };
                dlog_stmt_vec.insert(*id, v);
            }
            dlog_stmt_vec
        };

        purpose = "exchange paillier proof";
        let plkey_pf_send_vec: SparseVec<PaillierKeyProofs> = {
            let mut plkey_pf_send_vec = SparseVec::with_capacity(16);
            for (id, _pubsetup) in rgpsetup_ans_vec.iter() {
                let v = party_keys.phase3_proof_of_correct_key(&dlog_stmt_vec[id], &enc_keys[id]);
                plkey_pf_send_vec.insert(*id, v);
            }
            plkey_pf_send_vec
        };
        for (id, plpf) in plkey_pf_send_vec.iter() {
            self.postmsg_p2p(*id, purpose, plpf).await.catch_()?;
        }
        let plkey_pf_rec_vec: SparseVec<PaillierKeyProofs> = self
            .getmsg_mcast(key_mates.iter(), purpose)
            .await
            .catch_()?;

        let (
            (mut vss_scheme_inner, vss_scheme_outer),
            (secret_shares_inner, secret_shares_outer),
            _index,
        ) = party_keys
            .phase1_verify_com_phase3_verify_correct_key_phase2_distribute(
                &(Parameters {
                    threshold: group_config.threshold,
                    share_count: config.share_count,
                }, config.clone()),
                &_decom_vec,
                &com_vec.values_sorted_by_key_asc(),
                &plkey_pf_rec_vec.values_sorted_by_key_asc(),
                &enc_keys.values_sorted_by_key_asc(),
                &dlog_stmt_vec.values_sorted_by_key_asc(),
            )
            .catch("InvalidSecretKey","Either invalid commitment to keyshare in `Phase1` or invalid zkp of RSA moduli in `Phase3`")?;
        let secret_shares_inner: SparseVec<Scalar<Secp256k1>> = (0..secret_shares_inner.len())
            .map(|i| (i + 1, secret_shares_inner[i].clone()))
            .collect();
        let secret_shares_outer: SparseVec<Scalar<Secp256k1>> = (0..secret_shares_outer.len())
            .map(|i| (i + 1, secret_shares_outer[i].clone()))
            .collect();
        vss_scheme_inner.parameters.share_count = group_config.share_count;

        purpose = "exchange group key shares";
        for id in group_mates.iter() {
            let key: Vec<u8> = enc_keys.get(id).unwrap().to_bytes();
            let unencrypted: Vec<u8> = secret_shares_inner.get(id).unwrap().to_bytes().to_vec();
            let aead: AEAD = aes_encrypt(&key, &unencrypted).catch_()?;
            self.postmsg_p2p(*id, purpose, &aead).await.catch_()?;
        }
        let share_inner_vec: SparseVec<AEAD> = self
            .getmsg_mcast(group_mates.iter(), purpose)
            .await
            .catch_()?;

        purpose = "exchange all key shares";
        for mid in key_mates.iter() {
            let key: Vec<u8> = enc_keys.get(mid).unwrap().to_bytes();
            let unencrypted: Vec<u8> = secret_shares_outer.get(mid).unwrap().to_bytes().to_vec();
            let aead: AEAD = aes_encrypt(&key, &unencrypted).catch_()?;
            self.postmsg_p2p(*mid, purpose, &aead).await.catch_()?;
        }
        let share_outer_vec: SparseVec<AEAD> = self
            .getmsg_mcast(key_mates.iter(), purpose)
            .await
            .catch_()?;

        let mut party_shares_inner: SparseVec<Scalar<Secp256k1>> = SparseVec::new();
        for id in group_mates.iter() {
            if *id == my_id {
                party_shares_inner.insert(*id, secret_shares_inner.get(id).ifnone_()?.clone());
            } else {
                let aead = share_inner_vec.get(id).ifnone_()?;
                let key = enc_keys.get(id).unwrap().to_bytes();
                let decrypted = aes_decrypt(&key, &aead).catch_()?;
                party_shares_inner
                    .insert(*id, Scalar::<Secp256k1>::from_bytes(&decrypted).catch_()?);
            }
        }

        let mut party_shares_outer: SparseVec<Scalar<Secp256k1>> = SparseVec::new();
        for id in key_mates.iter() {
            if *id == my_id {
                party_shares_outer.insert(*id, secret_shares_outer[id].clone());
            } else {
                let aead = share_outer_vec.get(id).ifnone_()?;
                let key = enc_keys.get(id).unwrap().to_bytes();
                let decrypted = aes_decrypt(&key, &aead).catch_()?;
                party_shares_outer
                    .insert(*id, Scalar::<Secp256k1>::from_bytes(&decrypted).catch_()?);
            }
        }

        purpose = "exchange vss inner scheme";
        self.postmsg_mcast(key_mates.iter(), purpose, &vss_scheme_inner)
            .await
            .catch_()?;
        let vss_inner_vec: SparseVec<VerifiableSS<Secp256k1>> = self
            .getmsg_mcast(key_mates.iter(), purpose)
            .await
            .catch_()?;

        purpose = "exchange vss outer scheme";
        self.postmsg_mcast(key_mates.iter(), purpose, &vss_scheme_outer)
            .await
            .catch_()?;
        let vss_outer_vec: SparseVec<VerifiableSS<Secp256k1>> = self
            .getmsg_mcast(key_mates.iter(), purpose)
            .await
            .catch_()?;

        let _point_inner_vec = point_inner_vec.values_sorted_by_key_asc();
        let _point_outer_vec = point_outer_vec.values_sorted_by_key_asc();
        let y_vec = (_point_inner_vec.as_slice(), _point_outer_vec.as_slice());
        let (mut shared_keys, dlog_proof) = {
            let params = (&group_config, &config);
            let _party_shares_inner = party_shares_inner.values_sorted_by_key_asc();
            let _party_shares_outer = party_shares_outer.values_sorted_by_key_asc();
            let secret_shares_vec = (
                _party_shares_inner.as_slice(),
                _party_shares_outer.as_slice(),
            );
            let _vss_inner_vec = vss_inner_vec.values_sorted_by_key_asc();
            let _vss_outer_vec = vss_outer_vec.values_sorted_by_key_asc();
            let vss_scheme_vec = (_vss_inner_vec.as_slice(), _vss_outer_vec.as_slice());
            party_keys
                .phase2_verify_vss_construct_keypair_phase3_pok_dlog(
                    params,
                    y_vec,
                    secret_shares_vec,
                    vss_scheme_vec,
                    my_id as u16,
                )
                .catch(
                    "InvalidSecretKey",
                    "Invalid verifiable secret sharing in `Phase2`",
                )?
        };
        shared_keys.y = y_sum.clone();

        purpose = "exchange dlog proof";
        self.postmsg_mcast(key_mates.iter(), purpose, &dlog_proof)
            .await
            .catch_()?;
        let dlog_proof_vec: SparseVec<(
            DLogProof<Secp256k1, Sha256>,
            DLogProof<Secp256k1, Sha256>,
        )> = self
            .getmsg_mcast(key_mates.iter(), purpose)
            .await
            .catch_()?;
        Keys::verify_dlog_proofs(
            &config,
            dlog_proof_vec.values_sorted_by_key_asc().as_slice(),
            y_vec,
        )
        .catch("DlogProofFailed", "Bad dlog proof of `x_i` in `Phase3`")?;

        let keystore = KeyStore {
            party_keys,
            shared_keys,
            chain_code: {
                let pk_long = y_sum.to_bytes(false);
                let chain_code: ChainCode = Sha512::digest(&pk_long)
                    .get(..32)
                    .ifnone_()?
                    .try_into()
                    .unwrap();
                chain_code
            },
            vss_inner_vec: vss_inner_vec.clone(),
            vss_outer_vec: vss_outer_vec.clone(),
            paillier_keys: {
                let mut paillier_keys = SparseVec::with_capacity(16);
                for (id, com) in com_vec.iter() {
                    paillier_keys.insert(*id, com.e.clone());
                }
                paillier_keys
            },
            dlog_stmt_vec: dlog_stmt_vec.clone(),
            key_arch: KeyArch::default(),
            member_id: my_id,
        };

        let root_xpub = keystore.attr_root_xpub().catch_()?;
        self.terminate_session(SessionFruitValue::RootXpub(root_xpub))
            .await
            .catch_()?;

        Ok(keystore)
    }
}

pub fn scalar_split_inner_outer(
    num: &Scalar<Secp256k1>,
    ids: Vec<usize>,
) -> SparseVec<(Scalar<Secp256k1>, Scalar<Secp256k1>)> {
    let count = ids.len();
    if count == 1 {
        let k = ids[0];
        let v = (num.clone(), num.clone());
        SparseVec::from([(k, v)])
    } else {
        let mut partition_inner: SparseVec<Scalar<Secp256k1>> = SparseVec::with_capacity(16);
        let mut partition_outer: SparseVec<Scalar<Secp256k1>> = SparseVec::with_capacity(16);
        for j in 0..count - 1 {
            partition_inner.insert(ids[j], Scalar::<Secp256k1>::random());
            partition_outer.insert(ids[j], Scalar::<Secp256k1>::random());
        }
        let inner_sum: Scalar<Secp256k1> = partition_inner.values().sum();
        let outer_sum: Scalar<Secp256k1> = partition_outer.values().sum();
        partition_inner.insert(ids[count - 1], num - inner_sum);
        partition_outer.insert(ids[count - 1], num - outer_sum);

        let mut ret = SparseVec::with_capacity(16);
        for id in &ids {
            ret.insert(
                *id,
                (
                    partition_inner.get(id).unwrap().clone(),
                    partition_outer.get(id).unwrap().clone(),
                ),
            );
        }
        ret
    }
}
