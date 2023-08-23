use std::ops::Deref;

use crate::algo::party_i::SignatureRecid;
use curv::elliptic::curves::{Point, Scalar, Secp256k1};
use serde::{Deserialize, Serialize};
use xuanmi_base_support::*;

use super::{bigint_from_hex, bigint_to_hex, bytes_from_hex, bytes_to_hex};

pub struct Signature {
    pub sig_r: Scalar<Secp256k1>,
    pub sig_s: Scalar<Secp256k1>,
    pub recid: u8,
    pub pk: Point<Secp256k1>,
    pub msg_hashed: Vec<u8>,
}

impl Signature {
    pub fn new(rec: &SignatureRecid, pk: &Point<Secp256k1>, msg_hashed: &[u8]) -> Signature {
        Signature {
            sig_r: rec.r.clone(),
            sig_s: rec.s.clone(),
            recid: rec.recid,
            pk: pk.clone(),
            msg_hashed: Vec::from(msg_hashed),
        }
    }

    pub fn from_json(json: &str) -> Outcome<Signature> {
        let ss: SignatureSerde = json_to_obj(json)?;
        let so = Signature {
            sig_r: Scalar::from_bigint(&bigint_from_hex(&ss.sig_r)?),
            sig_s: Scalar::from_bigint(&bigint_from_hex(&ss.sig_s)?),
            recid: ss.recid,
            pk: Point::from_bytes(&bytes_from_hex(&ss.pk)?).catch("Signaturexception", "")?,
            msg_hashed: bytes_from_hex(&ss.msg_hashed)?,
        };
        Ok(so)
    }

    pub fn to_json(&self) -> Outcome<String> {
        let ss = SignatureSerde {
            sig_r: bigint_to_hex(&self.sig_r.to_bigint()),
            sig_s: bigint_to_hex(&self.sig_s.to_bigint()),
            recid: self.recid,
            pk: bytes_to_hex(&self.pk.to_bytes(true).deref()),
            msg_hashed: bytes_to_hex(&self.msg_hashed),
        };
        obj_to_json(&ss)
    }

    pub fn to_json_pretty(&self) -> Outcome<String> {
        let ss = SignatureSerde {
            sig_r: bigint_to_hex(&self.sig_r.to_bigint()),
            sig_s: bigint_to_hex(&self.sig_s.to_bigint()),
            recid: self.recid,
            pk: bytes_to_hex(&self.pk.to_bytes(true).deref()),
            msg_hashed: bytes_to_hex(&self.msg_hashed),
        };
        obj_to_json_pretty(&ss)
    }
}

#[derive(Clone, Serialize, Deserialize)]
struct SignatureSerde {
    sig_r: String, // bigint-hex:blabla
    sig_s: String, // bigint-hex:blabla
    recid: u8,
    pk: String,         // bytes-hex:blabla
    msg_hashed: String, // bytes-hex:blabla
}
