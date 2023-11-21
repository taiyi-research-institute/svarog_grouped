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
use zk_paillier::zkproofs::DLogStatement;

use super::{aes, *};
use crate::mpc_member::*;
use crate::{mta::range_proofs::*, util::*};

#[async_trait]
pub trait AlgoKeygen {
    async fn algo_keygen(&mut self) -> Outcome<KeyStore>;
}

#[async_trait]
impl AlgoKeygen for MpcMember {
    async fn algo_keygen(&mut self) -> Outcome<KeyStore> {
        let config = Parameters {
            threshold: (self.attr_key_quorum() - 1) as u16,
            share_count: self.attr_n_registered() as u16,
        };
        let group_config = Parameters {
            threshold: (self.attr_gruop_quorum() - 1) as u16,
            share_count: self.attr_group_n_registered() as u16,
        };
        let my_id = self.attr_member_id();
        let my_group_id = self.attr_group_id();

        let party_keys = Keys::create_with_safe_prime(self.attr_member_id() as u16); // instead of kzen::Keys::create(my_id)
        let _mnemonic = Mnemonic::from_entropy(
            (&party_keys.u_i.0 + &party_keys.u_i.1).to_bytes().as_ref(),
            Language::English,
        )
        .catch_()?;
        let _phrase: String = _mnemonic.phrase().to_string();

        let mut purpose = "commitment";
        let (bc_i, decom_i) = party_keys.phase1_com_decom();
        self.post_message(MpcPeer::All(), purpose, &bc_i)
            .await
            .catch_()?;
        let com_vec: SparseVec<KeyGenBroadcastMessage1> =
            self.get_message(MpcPeer::All(), purpose).await.catch_()?;

        purpose = "decommitment";
        self.post_message(MpcPeer::All(), purpose, &decom_i)
            .await
            .catch_()?;
        let decom_vec: SparseVec<KeyGenDecommitMessage1> =
            self.get_message(MpcPeer::All(), purpose).await.catch_()?;
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

        let decom_vec = decom_vec.values_sorted_by_key_asc();
        let (decom_head, decom_tail) = decom_vec.split_at(1);
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
        self.post_message(MpcPeer::All(), purpose, &range_proof_public_setup)
            .await
            .catch_()?;
        let rgpsetup_ans_vec: SparseVec<ZkpPublicSetup> =
            self.get_message(MpcPeer::All(), purpose).await.catch_()?;
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
            self.post_message(MpcPeer::Member(*id), purpose, plpf)
                .await
                .catch_()?;
        }
        let plkey_pf_rec_vec: SparseVec<PaillierKeyProofs> =
            self.get_message(MpcPeer::All(), purpose).await.catch_()?;

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
                &decom_vec,
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
        for id in self.attr_group_members() {
            let key: Vec<u8> = enc_keys.get(id).unwrap().to_bytes();
            let unencrypted: Vec<u8> = secret_shares_inner.get(id).unwrap().to_bytes().to_vec();
            let aead: AEAD = aes::aes_encrypt(&key, &unencrypted).catch_()?;
            self.post_message(MpcPeer::Member(*id), purpose, &aead)
                .await
                .catch_()?;
        }
        let share_inner_vec: SparseVec<AEAD> = self
            .get_message(MpcPeer::Group(my_group_id), purpose)
            .await
            .catch_()?;

        purpose = "exchange all key shares";
        for (mid, _gid) in self.attr_all_registered_members() {
            let key: Vec<u8> = enc_keys.get(mid).unwrap().to_bytes();
            let unencrypted: Vec<u8> = secret_shares_outer.get(mid).unwrap().to_bytes().to_vec();
            let aead: AEAD = aes::aes_encrypt(&key, &unencrypted).catch_()?;
            self.post_message(MpcPeer::Member(*mid), purpose, &aead)
                .await
                .catch_()?;
        }
        let share_outer_vec: SparseVec<AEAD> =
            self.get_message(MpcPeer::All(), purpose).await.catch_()?;

        let mut party_shares_inner: SparseVec<Scalar<Secp256k1>> = SparseVec::new();
        for id in self.attr_group_members() {
            if *id == my_id {
                party_shares_inner.insert(*id, secret_shares_inner.get(id).ifnone_()?.clone());
            } else {
                let aead = share_inner_vec.get(id).ifnone_()?;
                let key = enc_keys.get(id).unwrap().to_bytes();
                let decrypted = aes::aes_decrypt(&key, &aead).catch_()?;
                party_shares_inner
                    .insert(*id, Scalar::<Secp256k1>::from_bytes(&decrypted).catch_()?);
            }
        }

        let mut party_shares_outer: SparseVec<Scalar<Secp256k1>> = SparseVec::new();
        for (id, _gid) in self.attr_all_registered_members() {
            if *id == my_id {
                party_shares_outer.insert(*id, secret_shares_outer[id].clone());
            } else {
                let aead = share_outer_vec.get(id).ifnone_()?;
                let key = enc_keys.get(id).unwrap().to_bytes();
                let decrypted = aes::aes_decrypt(&key, &aead).catch_()?;
                party_shares_outer
                    .insert(*id, Scalar::<Secp256k1>::from_bytes(&decrypted).catch_()?);
            }
        }

        purpose = "exchange vss inner scheme";
        self.post_message(MpcPeer::All(), purpose, &vss_scheme_inner)
            .await
            .catch_()?;
        let vss_inner_vec: SparseVec<VerifiableSS<Secp256k1>> =
            self.get_message(MpcPeer::All(), purpose).await.catch_()?;

        purpose = "exchange vss outer scheme";
        self.post_message(MpcPeer::All(), purpose, &vss_scheme_outer)
            .await
            .catch_()?;
        let vss_outer_vec: SparseVec<VerifiableSS<Secp256k1>> =
            self.get_message(MpcPeer::All(), purpose).await.catch_()?;

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
        self.post_message(MpcPeer::All(), purpose, &dlog_proof)
            .await
            .catch_()?;
        let dlog_proof_vec: SparseVec<(
            DLogProof<Secp256k1, Sha256>,
            DLogProof<Secp256k1, Sha256>,
        )> = self.get_message(MpcPeer::All(), purpose).await.catch_()?;
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
            vss_schemes_inner: vss_inner_vec.clone(),
            vss_schemes_outer: vss_outer_vec.clone(),
            paillier_keys: {
                let mut paillier_keys = SparseVec::with_capacity(16);
                for (id, com) in com_vec.iter() {
                    paillier_keys.insert(*id, com.e.clone());
                }
                paillier_keys
            },
            key_arch: KeyArch::from(self.attr_session_config()),
            member_id: my_id,
        };

        let root_xpub = keystore.attr_root_xpub().catch_()?;
        self.terminate_session(SessionFruitValue::RootXpub(root_xpub))
            .await
            .catch_()?;

        Ok(keystore)
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub struct KeyStore {
    pub party_keys: Keys,
    pub shared_keys: SharedKeys,
    pub chain_code: [u8; 32],
    pub vss_schemes_inner: SparseVec<VerifiableSS<Secp256k1>>,
    pub vss_schemes_outer: SparseVec<VerifiableSS<Secp256k1>>,
    pub paillier_keys: SparseVec<EncryptionKey>,

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

#[derive(Clone, Serialize, Deserialize)]
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
