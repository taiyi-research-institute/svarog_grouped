use std::{
    collections::{HashMap, HashSet},
    ops::Deref,
};

use super::{scalar_split, KeyStore};
use crate::{
    assert_throw,
    biz_algo::{aes_decrypt, aes_encrypt, KeyArch, AEAD},
    exception::*,
    gg18::{
        feldman_vss::VerifiableSS,
        multi_party_ecdsa::{KeyGenBroadcastMessage1, KeyGenDecommitMessage1, Keys},
    },
    MpcMember,
};
use curv::{
    arithmetic::Converter,
    cryptographic_primitives::{
        commitments::{hash_commitment::HashCommitment, traits::Commitment},
        proofs::sigma_dlog::DLogProof,
    },
    elliptic::curves::{Point, Scalar, Secp256k1},
    BigInt,
};
use paillier::EncryptionKey;
use sha2::Sha256;
use tonic::async_trait;

#[async_trait]
pub trait AlgoReshare {
    async fn exchange_aes_keys(&self) -> Outcome<HashMap<u16, BigInt>>;
    async fn algo_reshare_provider(&self, keystore: &KeyStore) -> Outcome<()>;
    async fn algo_reshare_consumer(&self) -> Outcome<KeyStore>;
}

#[async_trait]
impl AlgoReshare for MpcMember {
    async fn exchange_aes_keys(&self) -> Outcome<HashMap<u16, BigInt>> {
        let mut purpose: &str;
        // Exchange AES keys, so that the mpc manager won't know what he is delivering.
        let temp_party_keys: Keys = Keys::create_casually(0 as u16);
        let (temp_com, temp_decom) = temp_party_keys.phase1_broadcast_phase3_proof_of_correct_key();

        purpose = "temp_com";
        self.postmsg_mcast(self.member_attending.iter(), purpose, &temp_com)
            .await
            .catch_()?;
        let temp_com_kv: HashMap<u16, KeyGenBroadcastMessage1> = self
            .getmsg_mcast(self.member_attending.iter(), purpose)
            .await
            .catch_()?;

        purpose = "temp_decom";
        self.postmsg_mcast(self.member_attending.iter(), purpose, &temp_decom)
            .await
            .catch_()?;
        let temp_decom_kv: HashMap<u16, KeyGenDecommitMessage1> = self
            .getmsg_mcast(self.member_attending.iter(), purpose)
            .await
            .catch_()?;

        for member_id in self.member_attending.iter() {
            let temp_com_i = &temp_com_kv[member_id];
            let temp_decom_i = &temp_decom_kv[member_id];
            temp_com_i
                .correct_key_proof
                .verify(&temp_com_i.e, zk_paillier::zkproofs::SALT_STRING)
                .catch("", "Invalid key")?;
            let hashcom_i =
                HashCommitment::<Sha256>::create_commitment_with_user_defined_randomness(
                    &BigInt::from_bytes(temp_decom_i.y_i.to_bytes(true).deref()),
                    &temp_decom_i.blind_factor,
                );
            assert_throw!(temp_com_i.com == hashcom_i, "Invalid commitment");
        }

        let mut aeskey_kv: HashMap<u16, BigInt> = HashMap::new();
        for (member_id, temp_decom_i) in temp_decom_kv.iter() {
            let enc_key = &temp_decom_i.y_i * &temp_party_keys.u_i;
            let enc_key = enc_key.x_coord().ifnone_()?;
            aeskey_kv.insert(*member_id, enc_key);
        }

        Ok(aeskey_kv)
    }

    async fn algo_reshare_provider(&self, keystore: &KeyStore) -> Outcome<()> {
        let mut purpose: &str;
        let my_id = self.member_id;
        let my_group_id = self.group_id;
        let all_participants: HashSet<u16> = self.member_attending.clone();
        let key_receivers: HashSet<u16> = self.reshare_members.clone();
        let key_providers: HashSet<u16> = all_participants
            .difference(&key_receivers)
            .cloned()
            .collect();
        println!(
            "my_id: {}, my_group_id: {}, key provider",
            my_id, my_group_id
        );

        let aeskey_kv = self.exchange_aes_keys().await.catch_()?;
        println!("Exchanged AES keys");

        purpose = "wi_aead_kvj";
        let lambda =
            VerifiableSS::<Secp256k1>::map_share_to_new_params(my_id, &key_providers).catch_()?;
        let wi = &lambda * &keystore.shared_keys.x_i;
        let wi_kvj: HashMap<u16, Scalar<Secp256k1>> = scalar_split(&wi, &key_receivers);
        let mut wi_aead_kvj: HashMap<u16, AEAD> = HashMap::new();
        for (receiver_id, wij) in wi_kvj.iter() {
            let key_j = aeskey_kv.get(receiver_id).ifnone_()?;
            let key_j = BigInt::to_bytes(key_j);
            let plain_j = BigInt::to_bytes(&wij.to_bigint());
            let aead_j = aes_encrypt(&key_j, &plain_j).catch_()?;
            wi_aead_kvj.insert(*receiver_id, aead_j);
        }
        for (receiver_id, wi_aeadj) in wi_aead_kvj.iter() {
            self.postmsg_p2p(*receiver_id, purpose, wi_aeadj)
                .await
                .catch_()?;
        }

        purpose = "y_sum, chain_code";
        let expected_y_sum =
            Point::<Secp256k1>::from_bytes(&keystore.attr_root_pk(true)).catch_()?;
        let chain_code: Vec<u8> = keystore.chain_code.iter().cloned().collect();
        self.postmsg_mcast(key_receivers.iter(), purpose, &(expected_y_sum, chain_code))
            .await
            .catch_()?;

        Ok(())
    }

    async fn algo_reshare_consumer(&self) -> Outcome<KeyStore> {
        let mut purpose: &str;
        let my_id: u16 = self.member_id;
        let my_group_id: u16 = self.group_id;
        let all_participants: HashSet<u16> = self.member_attending.clone();
        let key_receivers: HashSet<u16> = self.reshare_members.clone();
        let key_providers: HashSet<u16> = all_participants
            .difference(&key_receivers)
            .cloned()
            .collect();
        println!(
            "my_id: {}, my_group_id: {} (in session)",
            my_id, my_group_id
        );

        let aeskey_kv = self.exchange_aes_keys().await.catch_()?;
        println!("Exchanged AES keys");

        purpose = "wi_aead_kvj";
        let wji_aead_kv: HashMap<u16, AEAD> = self
            .getmsg_mcast(key_providers.iter(), purpose)
            .await
            .catch_()?;
        let mut wji_vec: Vec<Scalar<Secp256k1>> = Vec::new();
        for (provider_id, wji_aead) in &wji_aead_kv {
            let key_i = aeskey_kv.get(provider_id).ifnone_()?;
            let key_i = BigInt::to_bytes(key_i);
            let plain_i = aes_decrypt(&key_i, wji_aead).catch_()?;
            let wji = Scalar::<Secp256k1>::from_bigint(&BigInt::from_bytes(plain_i.deref()));
            wji_vec.push(wji);
        }
        let u_j: Scalar<Secp256k1> = wji_vec.iter().sum();

        println!("Consumer got party_keys");

        purpose = "y_sum, chain_code";
        let y_sum_chain_code_kv: HashMap<u16, (Point<Secp256k1>, Vec<u8>)> = self
            .getmsg_mcast(key_providers.iter(), purpose)
            .await
            .catch_()?;
        let mut it = y_sum_chain_code_kv.values().peekable();
        let _obj = it.next().cloned().ifnone_()?;
        let expected_y_sum = _obj.0;
        let chain_code = _obj.1;
        assert_throw!(chain_code.len() == 32, "Invalid chain_code length");
        for (y_sum_i, chain_code_i) in it {
            assert_throw!(y_sum_i == &expected_y_sum, "Inconsistent y_sum");
            assert_throw!(chain_code_i == &chain_code, "Inconsistent chain_code");
        }
        let chain_code: [u8; 32] = chain_code.try_into().unwrap();

        println!("Consumer got expected_y_sum and chain_code");

        /* ===== FINISH SECRET SHARING ===== */

        let min_receiver_id = self.reshare_members.iter().min().ifnone_()?;
        let min_receiver_group_id = self.member_group.get(min_receiver_id).ifnone_()?;
        let my_id: u16 = self.member_id - min_receiver_id + 1;
        let my_group_id: u16 = self.group_id - min_receiver_group_id + 1;
        let mut key_mates: HashSet<u16> = HashSet::new();
        let mut key_mates_others: HashSet<u16> = HashSet::new();
        for member_id in self.reshare_members.iter() {
            let member_id: u16 = member_id - min_receiver_id + 1;
            key_mates.insert(member_id);
            if member_id != my_id {
                key_mates_others.insert(member_id);
            }
        }
        let mut tweaked_self = self.clone();
        tweaked_self.member_id = my_id;
        println!(
            "my_id: {}, my_group_id: {} (aligned to incoming key)",
            my_id, my_group_id
        );

        println!("Searching for safe prime. This may take a while...");
        let party_keys = Keys::create_safely_from(&u_j, my_id);
        println!("Found safe prime.");
        let (com, decom) = party_keys.phase1_broadcast_phase3_proof_of_correct_key();

        purpose = "com";
        tweaked_self.postmsg_mcast(key_mates.iter(), purpose, &com)
            .await
            .catch_()?;
        let com_kv: HashMap<u16, KeyGenBroadcastMessage1> = tweaked_self
            .getmsg_mcast(key_mates.iter(), purpose)
            .await
            .catch_()?;

        purpose = "decom";
        tweaked_self.postmsg_mcast(key_mates.iter(), purpose, &decom)
            .await
            .catch_()?;
        let decom_kv: HashMap<u16, KeyGenDecommitMessage1> = tweaked_self
            .getmsg_mcast(key_mates.iter(), purpose)
            .await
            .catch_()?;

        let aeskey_kv: HashMap<u16, BigInt> = {
            let mut res = HashMap::new();
            for (member_id, decom) in decom_kv.iter() {
                let aeskey = &decom.y_i * &party_keys.u_i;
                let aeskey = aeskey.x_coord().ifnone_()?;
                res.insert(*member_id, aeskey);
            }
            res
        };

        let y_kv: HashMap<u16, Point<Secp256k1>> = {
            let mut res = HashMap::new();
            for (member_id, decom) in decom_kv.iter() {
                res.insert(*member_id, decom.y_i.clone());
            }
            res
        };

        let y_sum: Point<Secp256k1> = y_kv.iter().fold(Point::zero(), |sum, (_, y)| sum + y);
        assert_throw!(y_sum == expected_y_sum, "Invalid mnemonic");

        println!("Exchanged commitment to ephemeral public keys.");

        let (vss_scheme, secret_share_kv) = party_keys
            .phase1_verify_com_phase3_verify_correct_key_phase2_distribute(
                &self.reshare_key_quorum - 1,
                &com_kv,
                &decom_kv,
            )
            .unwrap();

        println!("Generated vss schemes.");

        purpose = "secret share aes-p2p";
        for member_id in key_mates_others.iter() {
            let key: Vec<u8> = BigInt::to_bytes(&aeskey_kv[member_id]);
            let plain: Vec<u8> = BigInt::to_bytes(&secret_share_kv[member_id].to_bigint());
            let aead: AEAD = aes_encrypt(&key, &plain).catch_()?;
            tweaked_self.postmsg_p2p(*member_id, purpose, &aead)
                .await
                .catch_()?;
        }
        let aead_others_kv: HashMap<u16, AEAD> = tweaked_self
            .getmsg_mcast(key_mates_others.iter(), purpose)
            .await
            .catch_()?;

        let party_shares_kv: HashMap<u16, Scalar<Secp256k1>> = {
            let mut res = HashMap::new();
            res.insert(my_id, secret_share_kv[&my_id].clone());
            for (member_id, aead) in aead_others_kv.iter() {
                let key = aeskey_kv[member_id].to_bytes();
                let plain = aes_decrypt(&key, &aead).catch_()?;
                let party_share: Scalar<Secp256k1> = Scalar::from(BigInt::from_bytes(&plain));
                res.insert(*member_id, party_share);
            }
            res
        };

        println!("Exchanged secret shares.");

        purpose = "vss commitment";
        tweaked_self.postmsg_mcast(key_mates.iter(), purpose, &vss_scheme)
            .await
            .catch_()?;
        let vss_scheme_kv: HashMap<u16, VerifiableSS<Secp256k1>> = tweaked_self
            .getmsg_mcast(key_mates.iter(), purpose)
            .await
            .catch_()?;

        println!("Exchanged VSS commitments.");

        let (shared_keys, dlog_proof) = party_keys
            .phase2_verify_vss_construct_keypair_phase3_pok_dlog(
                &y_kv,
                &party_shares_kv,
                &vss_scheme_kv,
            )
            .unwrap();

        purpose = "dlog proof";
        tweaked_self.postmsg_mcast(key_mates.iter(), purpose, &dlog_proof)
            .await
            .catch_()?;
        let dlog_proof_kv: HashMap<u16, DLogProof<Secp256k1, Sha256>> = tweaked_self
            .getmsg_mcast(key_mates.iter(), purpose)
            .await
            .catch_()?;

        println!("Exchanged DLog proofs.");

        Keys::verify_dlog_proofs(&dlog_proof_kv).unwrap();

        println!("Verified DLog proofs.");

        let paillier_key_kv: HashMap<u16, EncryptionKey> = com_kv // plkey_i = bc_i.e
            .iter()
            .map(|(member_id, com)| (*member_id, com.e.clone()))
            .collect();

        let key_arch = KeyArch {
            key_quorum: self.key_quorum,
            group_quora: {
                let mut res = HashMap::new();
                for (group_id, group_quorum) in &self.group_quora {
                    if self.reshare_groups.contains(group_id) {
                        let new_group_id = *group_id + 1 - min_receiver_group_id;
                        res.insert(new_group_id, *group_quorum);
                    }
                }
                res
            },
            member_group: {
                let mut res = HashMap::new();
                for (member_id, group_id) in &self.member_group {
                    if self.reshare_members.contains(member_id) {
                        let new_member_id = member_id + 1 - min_receiver_id;
                        let new_group_id = group_id + 1 - min_receiver_group_id;
                        res.insert(new_member_id, new_group_id);
                    }
                }
                res
            },
        };

        let keystore = KeyStore {
            party_keys,
            shared_keys,
            chain_code,
            vss_scheme_kv,
            paillier_key_kv,
            key_arch,
            member_id: my_id,
        };

        Ok(keystore)
    }
}
