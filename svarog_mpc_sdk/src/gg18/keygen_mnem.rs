//! This is a modified version of `gg18_keygen_client.rs` of Kzen Networks' implementation of GG18 key generation:
//! https://github.com/ZenGo-X/multi-party-ecdsa/blob/master/examples/gg18_keygen_client.rs
//!

use std::{collections::VecDeque, ops::Deref};

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

use super::*;
use crate::mpc_member::*;
use crate::util::*;

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
        let mut purpose = "";

        println!("mnemonic provider");

        let temp_party_keys: Keys = Keys::create(0 as u16);

        purpose = "temp commitment";
        let (temp_com, temp_decom) = temp_party_keys.phase1_broadcast_phase3_proof_of_correct_key();
        self.postmsg_mcast(key_mates.iter(), purpose, &temp_com)
            .await
            .catch_()?;
        let temp_com_svec: SparseVec<KeyGenBroadcastMessage1> = self
            .getmsg_mcast(key_mates.iter(), purpose)
            .await
            .catch_()?;

        purpose = "temp decommitment";
        self.postmsg_mcast(key_mates.iter(), purpose, &temp_decom)
            .await
            .catch_()?;
        let temp_decom_svec: SparseVec<KeyGenDecommitMessage1> = self
            .getmsg_mcast(key_mates.iter(), purpose)
            .await
            .catch_()?;

        println!("Exchanged temp commitment and decommitment.");

        for member_id in key_mates.iter() {
            let temp_com = &temp_com_svec[member_id];
            let temp_decom = &temp_decom_svec[member_id];
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

        let temp_aeskey_svec = {
            let mut res = SparseVec::with_capacity(16);
            for (id, temp_decom) in temp_decom_svec.iter() {
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

        let scalar_split = || -> SparseVec<Scalar<Secp256k1>> {
            let mut res = SparseVec::new();
            let mut members: VecDeque<usize> = key_mates_others.iter().cloned().collect();
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
            let temp_aeskey = BigInt::to_bytes(&temp_aeskey_svec[member_id]);
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
        let my_id = self.member_id;
        key_mates.insert(0);
        let mut purpose = "";

        println!("(One of) nemonic consumer");

        let mut temp_party_keys: Keys = Keys::create(my_id as u16);

        purpose = "temp commitment";
        let (temp_com, temp_decom) = temp_party_keys.phase1_broadcast_phase3_proof_of_correct_key();
        self.postmsg_mcast(key_mates.iter(), purpose, &temp_com)
            .await
            .catch_()?;
        let temp_com_svec: SparseVec<KeyGenBroadcastMessage1> = self
            .getmsg_mcast(key_mates.iter(), purpose)
            .await
            .catch_()?;

        purpose = "temp decommitment";
        self.postmsg_mcast(key_mates.iter(), purpose, &temp_decom)
            .await
            .catch_()?;
        let temp_decom_svec: SparseVec<KeyGenDecommitMessage1> = self
            .getmsg_mcast(key_mates.iter(), purpose)
            .await
            .catch_()?;

        println!("Exchanged temp commitment and decommitment.");

        for member_id in key_mates.iter() {
            let temp_com = &temp_com_svec[member_id];
            let temp_decom = &temp_decom_svec[member_id];
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

        let temp_aeskey_svec = {
            let mut res = SparseVec::with_capacity(16);
            for (id, temp_decom) in temp_decom_svec.iter() {
                let enc_key = temp_decom.y_i.clone() * temp_party_keys.u_i.clone();
                let enc_key = enc_key.x_coord().ifnone_()?;
                res.insert(*id, enc_key);
            }
            res
        };

        purpose = "share real sk";
        let obj: MnemProviderMessage = self.getmsg_p2p(0, purpose).await.catch_()?;
        let expected_y_sum = obj.y_sum;
        let temp_aeskey = BigInt::to_bytes(&temp_aeskey_svec[&0]);
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
        let member_id_to_idx = {
            let mut members: Vec<usize> = self.member_attending.iter().cloned().collect();
            members.sort();
            let mut res = SparseVec::new();
            for (idx, member_id) in members.iter().enumerate() {
                res.insert(*member_id, idx);
            }
            res
        };
        let config: Parameters = Parameters {
            threshold: (self.key_quorum - 1) as u16,
            share_count: key_mates.len() as u16,
        };

        let party_keys = temp_party_keys;
        let (com, decom) = party_keys.phase1_broadcast_phase3_proof_of_correct_key();

        purpose = "com";
        self.postmsg_mcast(key_mates.iter(), purpose, &com)
            .await
            .catch_()?;
        let com_svec: SparseVec<KeyGenBroadcastMessage1> = self
            .getmsg_mcast(key_mates.iter(), purpose)
            .await
            .catch_()?;

        purpose = "decom";
        self.postmsg_mcast(key_mates.iter(), purpose, &decom)
            .await
            .catch_()?;
        let decom_svec: SparseVec<KeyGenDecommitMessage1> = self
            .getmsg_mcast(key_mates.iter(), purpose)
            .await
            .catch_()?;

        let aeskey_svec: SparseVec<BigInt> = {
            let mut res = SparseVec::new();
            for (member_id, decom) in decom_svec.iter() {
                let aeskey = decom.y_i.clone() * party_keys.u_i.clone();
                let aeskey = aeskey.x_coord().ifnone_()?;
                res.insert(*member_id, aeskey);
            }
            res
        };

        let y_svec = {
            let mut res = SparseVec::new();
            for (member_id, decom) in decom_svec.iter() {
                res.insert(*member_id, decom.y_i.clone());
            }
            res
        };

        let y_sum: Point<Secp256k1> = y_svec.iter().fold(Point::zero(), |sum, (_, y)| sum + y);
        assert_throw!(y_sum == expected_y_sum, "Invalid mnemonic");

        println!("Exchanged commitment to ephemeral public keys.");

        let (vss_scheme, secret_share_vec, _) = party_keys
            .phase1_verify_com_phase3_verify_correct_key_phase2_distribute(
                &config,
                &decom_svec.values_sorted_by_key_asc(),
                &com_svec.values_sorted_by_key_asc(),
            )
            .catch_()?;

        let secret_share_svec = {
            let mut res: SparseVec<Scalar<Secp256k1>> = SparseVec::new();
            for (member_id, idx) in member_id_to_idx.iter() {
                res.insert(*member_id, secret_share_vec[*idx].clone());
            }
            res
        };

        println!("Generated secret shares.");

        purpose = "secret share aes-p2p";
        for member_id in key_mates_others.iter() {
            let key: Vec<u8> = BigInt::to_bytes(&aeskey_svec[member_id]);
            let plain: Vec<u8> = BigInt::to_bytes(&secret_share_svec[member_id].to_bigint());
            let aead: AEAD = aes_encrypt(&key, &plain).catch_()?;
            self.postmsg_p2p(*member_id, purpose, &aead)
                .await
                .catch_()?;
        }
        let aead_others_svec: SparseVec<AEAD> = self
            .getmsg_mcast(key_mates_others.iter(), purpose)
            .await
            .catch_()?;

        let party_shares_svec = {
            let mut res = SparseVec::new();
            res.insert(my_id, secret_share_svec[&my_id].clone());
            for (member_id, aead) in aead_others_svec.iter() {
                let key = aeskey_svec[member_id].to_bytes();
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
        let vss_scheme_svec: SparseVec<VerifiableSS<Secp256k1>> = self
            .getmsg_mcast(key_mates.iter(), purpose)
            .await
            .catch_()?;

        println!("Exchanged VSS commitments.");

        let y_vec = y_svec.values_sorted_by_key_asc();
        let (shared_keys, dlog_proof) = party_keys
            .phase2_verify_vss_construct_keypair_phase3_pok_dlog(
                &config,
                &y_vec,
                &party_shares_svec.values_sorted_by_key_asc(),
                &vss_scheme_svec.values_sorted_by_key_asc(),
                my_id as u16,
            )
            .catch_()?;

        purpose = "dlog proof";
        self.postmsg_mcast(key_mates.iter(), purpose, &dlog_proof)
            .await
            .catch_()?;
        let dlog_proof_svec: SparseVec<DLogProof<Secp256k1, Sha256>> = self
            .getmsg_mcast(key_mates.iter(), purpose)
            .await
            .catch_()?;

        println!("Exchanged DLog proofs.");

        Keys::verify_dlog_proofs(&config, &dlog_proof_svec.values_sorted_by_key_asc(), &y_vec)
            .catch_()?;

        println!("Verified DLog proofs.");

        let paillier_key_svec: SparseVec<EncryptionKey> = com_svec // plkey_i = bc_i.e
            .iter()
            .map(|(member_id, com)| (*member_id, com.e.clone()))
            .collect();

        let keystore = KeyStore {
            party_keys,
            shared_keys,
            chain_code,
            vss_scheme_svec,
            paillier_key_svec,
            key_arch: KeyArch::default(),
            member_id: my_id,
        };
        Ok(keystore)
    }
}
