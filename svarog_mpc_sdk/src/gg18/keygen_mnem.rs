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
        let (temp_com, temp_decom) =
            temp_party_keys.phase1_broadcast_phase3_proof_of_correct_key();
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

        //     party_keys.u_i = partition[member_id_to_idx[&my_id]].clone();
        //     party_keys.y_i = &partition[member_id_to_idx[&my_id]] * Point::<Secp256k1>::generator();
        //     chain_code
        // } else {
        //     let (aead_pack_i1, aead_pack_i2): (AEAD, AEAD) =
        //         self.getmsg_p2p(mnem_id, purpose).await.catch_()?;

        //     let key = BigInt::to_bytes(&aeskey_svec[&mnem_id]);
        //     let mut out = aes_decrypt(&key, &aead_pack_i1).catch_()?;
        //     let out_bn = BigInt::from_bytes(&out);
        //     let out_fe = Scalar::<Secp256k1>::from(&out_bn);
        //     // (party_keys.u_i, party_keys.y_i) =
        //     //     (out_fe.clone(), &out_fe * Point::<Secp256k1>::generator());
        //     out = aes_decrypt(&key, &aead_pack_i2).catch_()?;
        //     assert_throw!(out.len() == 32, "Invalid chain code");
        //     out.try_into().unwrap()
        // };

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
        let (temp_com, temp_decom) =
            temp_party_keys.phase1_broadcast_phase3_proof_of_correct_key();
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

        let key_mates = self.member_attending.clone();
        let party_keys = temp_party_keys;
        todo!("mostly ordinary keygen");

    }
}
