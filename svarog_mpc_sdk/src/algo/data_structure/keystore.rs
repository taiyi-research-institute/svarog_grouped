use curv::{
    cryptographic_primitives::secret_sharing::feldman_vss::{ShamirSecretSharing, VerifiableSS},
    elliptic::curves::{secp256_k1::Secp256k1, Point, Scalar},
};
use paillier::{DecryptionKey, EncryptionKey};
use serde::{Deserialize, Serialize};
use serde_json;
use std::collections::HashMap;
use xuanmi_base_support::*;
use zk_paillier::zkproofs::DLogStatement;

pub use crate::algo::party_i::{Keys as GG18Keys, SharedKeys as GG18SharedKeys};

pub type Vss = VerifiableSS<Secp256k1>;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyStore {
    pub party_keys: GG18Keys,
    pub shared_keys: GG18SharedKeys,
    pub party_id: u16,
    pub vss_scheme_vec: (Vec<Vss>, Vec<Vss>),
    pub paillier_key_vec: Vec<EncryptionKey>,
    pub y_sum: Point<Secp256k1>,
    pub chain_code: [u8; 32],
    pub group_id: u16,
    pub group_division: HashMap<u16, Vec<u16>>,
    pub dlog_statement_vec: Vec<DLogStatement>,
}

impl KeyStore {
    pub fn to_json(&self) -> Outcome<String> {
        let ser = serialize_friendly::KeyStore::serialize(self);
        let json = serde_json::to_string(&ser).catch("ObjectToJsonException", "")?;
        Ok(json)
    }

    pub fn to_json_pretty(&self) -> Outcome<String> {
        let ser = serialize_friendly::KeyStore::serialize(self);
        let json = serde_json::to_string_pretty(&ser).catch("ObjectToJsonException", "")?;
        Ok(json)
    }

    pub fn from_json(json: &str) -> Outcome<Self> {
        let ser: serialize_friendly::KeyStore =
            serde_json::from_str(json).catch("JsonToObjectException", "")?;
        let obj: KeyStore = ser.deserialize()?;
        Ok(obj)
    }
}

mod serialize_friendly {
    use serde::{Deserialize, Serialize};
    use std::collections::HashMap;
    use std::{convert::TryInto, ops::Deref};
    use xuanmi_base_support::{throw, Exception, Outcome, TraitStdResultToOutcome};

    use super::super::{bigint_from_hex, bigint_to_hex, bytes_from_hex, bytes_to_hex};

    type Point = super::Point<super::Secp256k1>;
    type Scalar = super::Scalar<super::Secp256k1>;

    #[derive(Clone, Serialize, Deserialize)]
    struct DecryptionKey {
        p: String, // bigint_hex:
        q: String, // bigint_hex:
    }

    #[derive(Clone, Serialize, Deserialize)]
    struct EncryptionKey {
        n: String,  // bigint_hex:
        nn: String, // bigint_hex:
    }

    #[derive(Clone, Serialize, Deserialize)]
    struct GG18Keys {
        u_i: (String, String), // bytes_hex:
        y_i: (String, String), // bytes_hex:
        dk: DecryptionKey,
        ek: EncryptionKey,
        party_index: u16,
    }

    #[derive(Clone, Serialize, Deserialize)]
    struct ShamirSecretSharing {
        threshold: u16,
        share_count: u16,
    }

    #[derive(Clone, Serialize, Deserialize)]
    struct Vss {
        parameters: ShamirSecretSharing,
        commitments: Vec<String>, // Vec<bytes_hex:>
    }

    fn serialize_vss_list(src_vss_list: &[super::Vss]) -> Vec<Vss> {
        src_vss_list
            .iter()
            .map(|src_vss| Vss {
                parameters: ShamirSecretSharing {
                    threshold: src_vss.parameters.threshold,
                    share_count: src_vss.parameters.share_count,
                },
                commitments: src_vss
                    .commitments
                    .iter()
                    .map(|src_commitment| bytes_to_hex(src_commitment.to_bytes(true).deref()))
                    .collect::<Vec<String>>(),
            })
            .collect::<Vec<_>>()
    }

    #[derive(Clone, Serialize, Deserialize)]
    struct GG18SharedKeys {
        y: String,             // bytes_hex:
        x_i: (String, String), // bytes_hex:
    }

    #[derive(Clone, Serialize, Deserialize)]
    struct DLogStatement {
        N: String,  // bigint_hex:
        g: String,  // bigint_hex:
        ni: String, // bigint_hex:
    }

    #[derive(Clone, Serialize, Deserialize)]
    pub struct KeyStore {
        party_keys: GG18Keys,
        shared_keys: GG18SharedKeys,
        party_id: u16,
        vss_scheme_vec: (Vec<Vss>, Vec<Vss>),
        paillier_key_vec: Vec<EncryptionKey>,
        y_sum: String,      // bytes_hex:
        chain_code: String, // bytes_hex:
        group_id: u16,
        group_division: HashMap<u16, Vec<u16>>,
        dlog_statement_vec: Vec<DLogStatement>,
    }

    impl KeyStore {
        pub fn serialize(src: &super::KeyStore) -> Self {
            KeyStore {
                party_keys: GG18Keys {
                    u_i: (
                        bytes_to_hex(&src.party_keys.u_i.0.to_bytes().deref()),
                        bytes_to_hex(&src.party_keys.u_i.1.to_bytes().deref()),
                    ),
                    y_i: (
                        bytes_to_hex(&src.party_keys.y_i.0.to_bytes(true).deref()),
                        bytes_to_hex(&src.party_keys.y_i.1.to_bytes(true).deref()),
                    ),
                    dk: DecryptionKey {
                        p: bigint_to_hex(&src.party_keys.dk.p),
                        q: bigint_to_hex(&src.party_keys.dk.q),
                    },
                    ek: EncryptionKey {
                        n: bigint_to_hex(&src.party_keys.ek.n),
                        nn: bigint_to_hex(&src.party_keys.ek.nn),
                    },
                    party_index: src.party_keys.party_index,
                },
                shared_keys: GG18SharedKeys {
                    y: bytes_to_hex(&src.shared_keys.y.to_bytes(true).deref()),
                    x_i: (
                        bytes_to_hex(&src.shared_keys.x_i.0.to_bytes().deref()),
                        bytes_to_hex(&src.shared_keys.x_i.1.to_bytes().deref()),
                    ),
                },
                party_id: src.party_id,
                vss_scheme_vec: {
                    let vec_vss_inner = serialize_vss_list(&src.vss_scheme_vec.0);
                    let vec_vss_outer = serialize_vss_list(&src.vss_scheme_vec.1);
                    (vec_vss_inner, vec_vss_outer)
                },
                paillier_key_vec: {
                    let mut vec_plkey: Vec<EncryptionKey> =
                        Vec::with_capacity(src.paillier_key_vec.len());
                    for src_plkey in &src.paillier_key_vec {
                        let plkey = EncryptionKey {
                            n: bigint_to_hex(&src_plkey.n),
                            nn: bigint_to_hex(&src_plkey.nn),
                        };
                        vec_plkey.push(plkey);
                    }
                    vec_plkey
                },
                y_sum: bytes_to_hex(&src.y_sum.to_bytes(true).deref()),
                chain_code: bytes_to_hex(&src.chain_code),
                group_id: src.group_id,
                group_division: src.group_division.clone(),
                dlog_statement_vec: {
                    let mut vec_dlog_statement: Vec<DLogStatement> =
                        Vec::with_capacity(src.dlog_statement_vec.len());
                    for src_dlog_statement in &src.dlog_statement_vec {
                        let dlog_statement = DLogStatement {
                            N: bigint_to_hex(&src_dlog_statement.N),
                            g: bigint_to_hex(&src_dlog_statement.g),
                            ni: bigint_to_hex(&src_dlog_statement.ni),
                        };
                        vec_dlog_statement.push(dlog_statement);
                    }
                    vec_dlog_statement
                },
            }
        }

        pub fn deserialize(&self) -> Outcome<super::KeyStore> {
            const HexToPointException: &'static str = "HexToPointException";
            const HexToScalarException: &'static str = "HexToPointException";
            const InvalidLengthException: &'static str = "InvalidLengthException";
            let ret = super::KeyStore {
                party_keys: super::GG18Keys {
                    u_i: (
                        Scalar::from_bytes(&bytes_from_hex(&self.party_keys.u_i.0)?)
                            .catch(HexToScalarException, "")?,
                        Scalar::from_bytes(&bytes_from_hex(&self.party_keys.u_i.1)?)
                            .catch(HexToScalarException, "")?,
                    ),
                    y_i: (
                        Point::from_bytes(&bytes_from_hex(&self.party_keys.y_i.0)?)
                            .catch(HexToPointException, "")?,
                        Point::from_bytes(&bytes_from_hex(&self.party_keys.y_i.1)?)
                            .catch(HexToPointException, "")?,
                    ),
                    dk: super::DecryptionKey {
                        p: bigint_from_hex(&self.party_keys.dk.p)?,
                        q: bigint_from_hex(&self.party_keys.dk.q)?,
                    },
                    ek: super::EncryptionKey {
                        n: bigint_from_hex(&self.party_keys.ek.n)?,
                        nn: bigint_from_hex(&self.party_keys.ek.nn)?,
                    },
                    party_index: self.party_keys.party_index,
                },
                shared_keys: super::GG18SharedKeys {
                    y: Point::from_bytes(&bytes_from_hex(&self.shared_keys.y)?)
                        .catch(HexToPointException, "")?,
                    x_i: (
                        Scalar::from_bytes(&bytes_from_hex(&self.shared_keys.x_i.0)?)
                            .catch(HexToScalarException, "")?,
                        Scalar::from_bytes(&bytes_from_hex(&self.shared_keys.x_i.1)?)
                            .catch(HexToScalarException, "")?,
                    ),
                },
                party_id: self.party_id,
                vss_scheme_vec: {
                    let mut vec_vss_inner: Vec<super::Vss> =
                        Vec::with_capacity(self.vss_scheme_vec.0.len());
                    for self_vss in &self.vss_scheme_vec.0 {
                        let vss = super::Vss {
                            parameters: super::ShamirSecretSharing {
                                threshold: self_vss.parameters.threshold,
                                share_count: self_vss.parameters.share_count,
                            },
                            commitments: {
                                let mut vec_com: Vec<Point> =
                                    Vec::with_capacity(self_vss.commitments.len());
                                for self_com in &self_vss.commitments {
                                    let point = Point::from_bytes(&bytes_from_hex(&self_com)?)
                                        .catch(HexToPointException, "")?;
                                    vec_com.push(point);
                                }
                                vec_com
                            },
                        };
                        vec_vss_inner.push(vss);
                    }
                    let mut vec_vss_outer: Vec<super::Vss> =
                        Vec::with_capacity(self.vss_scheme_vec.1.len());
                    for self_vss in &self.vss_scheme_vec.1 {
                        let vss = super::Vss {
                            parameters: super::ShamirSecretSharing {
                                threshold: self_vss.parameters.threshold,
                                share_count: self_vss.parameters.share_count,
                            },
                            commitments: {
                                let mut vec_com: Vec<Point> =
                                    Vec::with_capacity(self_vss.commitments.len());
                                for self_com in &self_vss.commitments {
                                    let point = Point::from_bytes(&bytes_from_hex(&self_com)?)
                                        .catch(HexToPointException, "")?;
                                    vec_com.push(point);
                                }
                                vec_com
                            },
                        };
                        vec_vss_outer.push(vss);
                    }
                    (vec_vss_inner, vec_vss_outer)
                },
                paillier_key_vec: {
                    let mut vec_plkey: Vec<super::EncryptionKey> =
                        Vec::with_capacity(self.paillier_key_vec.len());
                    for self_plkey in &self.paillier_key_vec {
                        let plkey = super::EncryptionKey {
                            n: bigint_from_hex(&self_plkey.n)?,
                            nn: bigint_from_hex(&self_plkey.nn)?,
                        };
                        vec_plkey.push(plkey);
                    }
                    vec_plkey
                },
                y_sum: Point::from_bytes(&bytes_from_hex(&self.y_sum)?)
                    .catch(HexToPointException, "")?,
                chain_code: {
                    let bytes = bytes_from_hex(&self.chain_code)?;
                    if bytes.len() != 32 {
                        throw!(
                            name = InvalidLengthException,
                            ctx = &format!("Expected 32 bytes, provided {} bytes", bytes.len())
                        );
                    }
                    let chain_code: [u8; 32] = bytes.try_into().unwrap();
                    chain_code
                },
                group_id: self.group_id,
                group_division: self.group_division.clone(),
                dlog_statement_vec: {
                    let mut vec_dlog_statement: Vec<super::DLogStatement> =
                        Vec::with_capacity(self.dlog_statement_vec.len());
                    for self_dlog_statement in &self.dlog_statement_vec {
                        let dlog_statement = super::DLogStatement {
                            N: bigint_from_hex(&self_dlog_statement.N)?,
                            g: bigint_from_hex(&self_dlog_statement.g)?,
                            ni: bigint_from_hex(&self_dlog_statement.ni)?,
                        };
                        vec_dlog_statement.push(dlog_statement);
                    }
                    vec_dlog_statement
                },
            };
            Ok(ret)
        }
    }
}
