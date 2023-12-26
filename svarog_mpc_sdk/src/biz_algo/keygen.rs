//! This is a modified version of `gg18_keygen_client.rs` of Kzen Networks' implementation of GG18 key generation:
//! https://github.com/ZenGo-X/multi-party-ecdsa/blob/master/examples/gg18_keygen_client.rs
//!

use std::{collections::HashMap, ops::Deref};

use super::*;
use crate::{
    exception::*,
    gg18::{feldman_vss::*, multi_party_ecdsa::*},
    mpc_member::*,
};
use bip32::ChainCode; // chain_code = left half of SHA512(pk)
use bip39::{Language, Mnemonic};
use curv::{
    arithmetic::traits::Converter,
    cryptographic_primitives::proofs::sigma_dlog::DLogProof,
    elliptic::curves::{secp256_k1::Secp256k1, Point, Scalar},
    BigInt,
};
use paillier::EncryptionKey;
use sha2::{Digest, Sha256, Sha512};
use tonic::async_trait;

#[async_trait]
pub trait AlgoKeygen {
    async fn algo_keygen(&self) -> Outcome<KeyStore>;
}

#[async_trait]
impl AlgoKeygen for MpcMember {
    async fn algo_keygen(&self) -> Outcome<KeyStore> {
        let my_id = self.member_id;
        let my_group_id = self.group_id;
        let key_mates = self.member_attending.clone();
        let key_mates_others = {
            let mut res = key_mates.clone();
            res.remove(&my_id);
            res
        };
        println!("my_id: {}, my_group_id: {}", my_id, my_group_id);

        println!("Searching for safe prime. This may take a while...");
        let party_keys = Keys::create_safe_prime(my_id);
        println!("Found safe prime.");
        
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

        println!("Exchanged commitment to ephemeral public keys.");

        let (vss_scheme, secret_share_kv) = party_keys
            .phase1_verify_com_phase3_verify_correct_key_phase2_distribute(
                &self.key_quorum - 1,
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

        let chain_code = {
            let pkb_long = y_sum.to_bytes(false).deref().to_vec();
            let chain_code: ChainCode = Sha512::digest(&pkb_long)
                .get(..32)
                .ifnone_()?
                .try_into()
                .unwrap();
            chain_code
        };

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
