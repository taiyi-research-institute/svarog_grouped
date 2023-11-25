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
};
use sha2::{Sha256, Sha512};
use svarog_grpc::protogen::svarog::SessionConfig;
use tonic::async_trait;
use xuanmi_base_support::*;

use super::*;
use crate::{mpc_member::*, util::*};

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
        println!("my_id: {}, my_group_id: {}", my_id, my_group_id);

        let party_keys = Keys::create(my_id as u16);
        let _shard_mnem: String =
            Mnemonic::from_entropy(&party_keys.u_i.to_bytes(), Language::English)
                .catch_()?
                .phrase()
                .to_string();

        let (bc_i, decom_i) = party_keys.phase1_broadcast_phase3_proof_of_correct_key();

        let mut purpose = "com";
        self.postmsg_mcast(key_mates.iter(), purpose, &bc_i)
            .await
            .catch_()?;
        let com_svec: SparseVec<KeyGenBroadcastMessage1> = self
            .getmsg_mcast(key_mates.iter(), purpose)
            .await
            .catch_()?;
        assert_throw!(com_svec[&my_id].e == bc_i.e, "Broken message");

        purpose = "decom";
        self.postmsg_mcast(key_mates.iter(), purpose, &decom_i)
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
            vss_scheme_svec,
            paillier_key_svec,
            key_arch: KeyArch::default(),
            member_id: my_id,
        };
        Ok(keystore)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyStore {
    pub party_keys: Keys,
    pub shared_keys: SharedKeys,
    pub chain_code: [u8; 32],
    pub vss_scheme_svec: SparseVec<VerifiableSS<Secp256k1>>,
    pub paillier_key_svec: SparseVec<EncryptionKey>,

    pub key_arch: KeyArch,
    pub member_id: usize,
}

impl KeyStore {
    pub fn marshall(&self) -> Outcome<Vec<u8>> {
        let deflated = self.compress().catch_()?;
        Ok(deflated)
    }

    pub fn unmarshall(deflated: &[u8]) -> Outcome<Self> {
        let obj: Self = deflated.decompress().catch_()?;
        Ok(obj)
    }

    pub fn attr_root_xpub(&self) -> Outcome<String> {
        let pk_short = self.attr_root_pk(true);
        assert_throw!(pk_short.len() == 33, "Invalid pubkey length");
        let ex_pk = ExtendedKey {
            prefix: Prefix::XPUB,
            attrs: ExtendedKeyAttrs {
                depth: 0u8,
                parent_fingerprint: [0u8; 4],
                child_number: ChildNumber(0u32),
                chain_code: self.chain_code.clone(),
            },
            key_bytes: pk_short.try_into().unwrap(),
        };
        Ok(ex_pk.to_string())
    }

    pub fn attr_root_pk(&self, compress: bool) -> Vec<u8> {
        let point = &self.shared_keys.y;
        let pk = point.to_bytes(compress).deref().to_vec();
        pk
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct KeyArch {
    pub key_quorum: usize,
    pub groups: Vec<svarog_grpc::protogen::svarog::Group>,
}

impl From<&SessionConfig> for KeyArch {
    fn from(config: &SessionConfig) -> Self {
        let key_quorum = config.key_quorum as usize;
        let groups = config.groups.clone();
        Self { key_quorum, groups }
    }
}
