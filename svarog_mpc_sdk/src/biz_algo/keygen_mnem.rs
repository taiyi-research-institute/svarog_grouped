//! This is a modified version of `gg18_keygen_client.rs` of Kzen Networks' implementation of GG18 key generation:
//! https://github.com/ZenGo-X/multi-party-ecdsa/blob/master/examples/gg18_keygen_client.rs
//!

use std::{
    collections::{HashMap, VecDeque},
    ops::Deref,
};

use super::*;
use crate::{
    assert_throw,
    exception::*,
    gg18::{
        feldman_vss::VerifiableSS,
        multi_party_ecdsa::{KeyGenBroadcastMessage1, KeyGenDecommitMessage1, Keys},
    },
    mpc_member::*,
};
use bip39::{Language, Mnemonic, Seed};
use bitcoin::util::bip32::ExtendedPrivKey;
use bitcoin::Network;
use curv::{
    arithmetic::traits::Converter,
    cryptographic_primitives::{
        commitments::hash_commitment::HashCommitment, commitments::traits::Commitment,
        proofs::sigma_dlog::DLogProof,
    },
    elliptic::curves::{secp256_k1::Secp256k1, Point, Scalar},
    BigInt,
};
use paillier::EncryptionKey;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use tonic::async_trait;

#[async_trait]
pub trait AlgoKeygenMnem {
    async fn algo_keygen_provide_mnem(&self, mnem: &str, pwd: &str) -> Outcome<()>;
    async fn algo_keygen_consume_mnem(&self) -> Outcome<KeyStore>;
}

#[derive(Clone, Serialize, Deserialize)]
struct MnemProviderMessage {
    y_sum: Point<Secp256k1>,
    aead_key_part: AEAD,
    aead_chain_code: AEAD,
}

#[async_trait]
impl AlgoKeygenMnem for MpcMember {
    async fn algo_keygen_provide_mnem(&self, mnem: &str, pwd: &str) -> Outcome<()> {
        // a mnemonic provider has member_id == 0 and group_id == 0
        let mut key_mates = self.member_attending.clone();
        let key_mates_others = key_mates.clone();
        key_mates.insert(0);
        let mut purpose: &str;

        println!("mnemonic provider");

        let temp_party_keys: Keys = Keys::create_safe_prime(0 as u16);

        purpose = "temp commitment";
        let (temp_com, temp_decom) = temp_party_keys.phase1_broadcast_phase3_proof_of_correct_key();
        self.postmsg_mcast(key_mates.iter(), purpose, &temp_com)
            .await
            .catch_()?;
        let temp_com_kv: HashMap<u16, KeyGenBroadcastMessage1> = self
            .getmsg_mcast(key_mates.iter(), purpose)
            .await
            .catch_()?;

        purpose = "temp decommitment";
        self.postmsg_mcast(key_mates.iter(), purpose, &temp_decom)
            .await
            .catch_()?;
        let temp_decom_kv: HashMap<u16, KeyGenDecommitMessage1> = self
            .getmsg_mcast(key_mates.iter(), purpose)
            .await
            .catch_()?;

        println!("Exchanged temp commitment and decommitment.");

        for member_id in key_mates.iter() {
            let temp_com = &temp_com_kv[member_id];
            let temp_decom = &temp_decom_kv[member_id];
            temp_com
                .correct_key_proof
                .verify(&temp_com.e, zk_paillier::zkproofs::SALT_STRING)
                .catch("", "Invalid key")?;
            let hashcom = HashCommitment::<Sha256>::create_commitment_with_user_defined_randomness(
                &BigInt::from_bytes(temp_decom.y_i.to_bytes(true).deref()),
                &temp_decom.blind_factor,
            );
            assert_throw!(temp_com.com == hashcom, "Invalid commitment");
        }

        println!("Verified pre commitment and decommitment.");

        let temp_aeskey_kv = {
            let mut res = HashMap::with_capacity(16);
            for (id, temp_decom) in temp_decom_kv.iter() {
                let enc_key = temp_decom.y_i.clone() * temp_party_keys.u_i.clone();
                let enc_key = enc_key.x_coord().ifnone_()?;
                res.insert(*id, enc_key);
            }
            res
        };

        let seed = Seed::new(
            &Mnemonic::from_phrase(mnem, Language::English).catch_()?,
            pwd,
        );
        let seed_bytes: &[u8] = seed.as_bytes();
        let master_sk = ExtendedPrivKey::new_master(Network::Bitcoin, seed_bytes).catch_()?;
        let num_sk =
            Scalar::<Secp256k1>::from_bytes(&master_sk.private_key.secret_bytes()).catch_()?;
        let expected_y_sum =
            &Scalar::<Secp256k1>::from_bytes(&master_sk.private_key.secret_bytes()).catch_()?
                * Point::<Secp256k1>::generator();
        let chain_code = master_sk.chain_code.to_bytes();

        let scalar_split = || -> HashMap<u16, Scalar<Secp256k1>> {
            let mut res = HashMap::new();
            let mut members: VecDeque<u16> = key_mates_others.iter().cloned().collect();
            while members.len() > 1 {
                let member_id = members.pop_front().unwrap();
                res.insert(member_id, Scalar::<Secp256k1>::random());
            }
            let member_id = members.pop_front().unwrap();
            let partial_sum: Scalar<Secp256k1> = res.values().sum();
            res.insert(member_id, num_sk - partial_sum);
            res
        };

        let partition = scalar_split();

        purpose = "share real sk";
        for member_id in key_mates_others.iter() {
            let temp_aeskey = BigInt::to_bytes(&temp_aeskey_kv[member_id]);
            let plain_key_part = BigInt::to_bytes(&partition[member_id].to_bigint());
            let aead_key_part = aes_encrypt(&temp_aeskey, &plain_key_part).catch_()?;
            let aead_chain_code = aes_encrypt(&temp_aeskey, &chain_code).catch_()?;
            let obj = MnemProviderMessage {
                y_sum: expected_y_sum.clone(),
                aead_key_part,
                aead_chain_code,
            };
            self.postmsg_p2p(*member_id, purpose, &obj).await.catch_()?;
        }

        println!("The mnemonic provider have sent the key shares.");

        Ok(())
    }

    async fn algo_keygen_consume_mnem(&self) -> Outcome<KeyStore> {
        // a mnemonic provider has member_id == 0 and group_id == 0
        let mut key_mates = self.member_attending.clone();
        key_mates.insert(0);
        let my_id = self.member_id;
        let mut purpose: &str;

        println!(
            "member_id = {}, group_id = {}. One of mnemonic consumer(s).",
            my_id, self.group_id
        );

        let mut temp_party_keys: Keys = Keys::create_safe_prime(my_id as u16);

        purpose = "temp commitment";
        let (temp_com, temp_decom) = temp_party_keys.phase1_broadcast_phase3_proof_of_correct_key();
        self.postmsg_mcast(key_mates.iter(), purpose, &temp_com)
            .await
            .catch_()?;
        let temp_com_kv: HashMap<u16, KeyGenBroadcastMessage1> = self
            .getmsg_mcast(key_mates.iter(), purpose)
            .await
            .catch_()?;

        purpose = "temp decommitment";
        self.postmsg_mcast(key_mates.iter(), purpose, &temp_decom)
            .await
            .catch_()?;
        let temp_decom_kv: HashMap<u16, KeyGenDecommitMessage1> = self
            .getmsg_mcast(key_mates.iter(), purpose)
            .await
            .catch_()?;

        println!("Exchanged temp commitment and decommitment.");

        for member_id in key_mates.iter() {
            let temp_com = &temp_com_kv[member_id];
            let temp_decom = &temp_decom_kv[member_id];
            temp_com
                .correct_key_proof
                .verify(&temp_com.e, zk_paillier::zkproofs::SALT_STRING)
                .catch("", "Invalid key")?;
            let hashcom = HashCommitment::<Sha256>::create_commitment_with_user_defined_randomness(
                &BigInt::from_bytes(temp_decom.y_i.to_bytes(true).deref()),
                &temp_decom.blind_factor,
            );
            assert_throw!(temp_com.com == hashcom, "Invalid commitment");
        }

        println!("Verified pre commitment and decommitment.");

        let temp_aeskey_kv = {
            let mut res = HashMap::with_capacity(16);
            for (id, temp_decom) in temp_decom_kv.iter() {
                let enc_key = temp_decom.y_i.clone() * temp_party_keys.u_i.clone();
                let enc_key = enc_key.x_coord().ifnone_()?;
                res.insert(*id, enc_key);
            }
            res
        };

        purpose = "share real sk";
        let obj: MnemProviderMessage = self.getmsg_p2p(0, purpose).await.catch_()?;
        let expected_y_sum = obj.y_sum;
        let temp_aeskey = BigInt::to_bytes(&temp_aeskey_kv[&0]);
        let key_part_bytes = aes_decrypt(&temp_aeskey, &obj.aead_key_part).catch_()?;
        let key_part_bigint = BigInt::from_bytes(&key_part_bytes);
        let key_part = Scalar::<Secp256k1>::from(&key_part_bigint);

        temp_party_keys.u_i = key_part.clone();
        temp_party_keys.y_i = &key_part * Point::<Secp256k1>::generator();
        let chain_code_vu8: Vec<u8> = aes_decrypt(&temp_aeskey, &obj.aead_chain_code).catch_()?;
        assert_throw!(chain_code_vu8.len() == 32, "Invalid chain code");
        let chain_code: [u8; 32] = chain_code_vu8.try_into().unwrap();

        println!("One mnemonic consumer has received a key share.");

        /* ===== FINISH MNEMONIC SHARING ===== */

        let my_group_id = self.group_id;
        let key_mates = self.member_attending.clone();
        let key_mates_others = {
            let mut res = key_mates.clone();
            res.remove(&my_id);
            res
        };
        println!("my_id: {}, my_group_id: {}", my_id, my_group_id);

        let party_keys = temp_party_keys;
        let _shard_mnem: String =
            Mnemonic::from_entropy(&party_keys.u_i.to_bytes(), Language::English)
                .catch_()?
                .phrase()
                .to_string();

        let (com, decom) = party_keys.phase1_broadcast_phase3_proof_of_correct_key();

        let mut purpose = "com";
        self.postmsg_mcast(key_mates.iter(), purpose, &com)
            .await
            .catch_()?;
        let com_kv: HashMap<u16, KeyGenBroadcastMessage1> = self
            .getmsg_mcast(key_mates.iter(), purpose)
            .await
            .catch_()?;

        purpose = "decom";
        self.postmsg_mcast(key_mates.iter(), purpose, &decom)
            .await
            .catch_()?;
        let decom_kv: HashMap<u16, KeyGenDecommitMessage1> = self
            .getmsg_mcast(key_mates.iter(), purpose)
            .await
            .catch_()?;

        let aeskey_kv: HashMap<u16, BigInt> = {
            let mut res = HashMap::new();
            for (member_id, decom) in decom_kv.iter() {
                let aeskey = decom.y_i.clone() * party_keys.u_i.clone();
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
                &self.key_quorum - 1,
                &com_kv,
                &decom_kv,
            )
            .unwrap();

        println!("Generated secret shares.");

        purpose = "secret share aes-p2p";
        for member_id in key_mates_others.iter() {
            let key: Vec<u8> = BigInt::to_bytes(&aeskey_kv[member_id]);
            let plain: Vec<u8> = BigInt::to_bytes(&secret_share_kv[member_id].to_bigint());
            let aead: AEAD = aes_encrypt(&key, &plain).catch_()?;
            self.postmsg_p2p(*member_id, purpose, &aead)
                .await
                .catch_()?;
        }
        let aead_others_kv: HashMap<u16, AEAD> = self
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
        self.postmsg_mcast(key_mates.iter(), purpose, &vss_scheme)
            .await
            .catch_()?;
        let vss_scheme_kv: HashMap<u16, VerifiableSS<Secp256k1>> = self
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
        self.postmsg_mcast(key_mates.iter(), purpose, &dlog_proof)
            .await
            .catch_()?;
        let dlog_proof_kv: HashMap<u16, DLogProof<Secp256k1, Sha256>> = self
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

        let keystore = KeyStore {
            party_keys,
            shared_keys,
            chain_code,
            vss_scheme_kv,
            paillier_key_kv,
            key_arch: KeyArch::default(),
            member_id: my_id,
        };

        Ok(keystore)
    }
}
