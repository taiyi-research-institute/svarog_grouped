use std::ops::Deref;

use super::*;
use crate::{util::*, CompressAble, DecompressAble};
use bip32::{ChildNumber, ExtendedKey, ExtendedKeyAttrs, Prefix};
use curv::{
    cryptographic_primitives::secret_sharing::feldman_vss::VerifiableSS,
    elliptic::curves::Secp256k1,
};
use multi_party_ecdsa::protocols::multi_party_ecdsa::gg_2018::party_i::*;
use paillier::EncryptionKey;
use serde::{Deserialize, Serialize};
use svarog_grpc::protogen::svarog::SessionConfig;

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
