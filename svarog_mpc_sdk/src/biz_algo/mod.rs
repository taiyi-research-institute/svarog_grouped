mod keygen;
pub use keygen::*;
mod keystore;
pub use keystore::*;
mod keygen_mnem;
pub use keygen_mnem::*;
mod sign;
pub use sign::*;
mod hd;
pub use hd::*;
mod reshare;
pub use reshare::*;

use crate::exception::*;
use aes_gcm::{
    aead::{Aead, NewAead, Payload},
    Aes256Gcm, Nonce,
};
use curv::elliptic::curves::{Scalar, Secp256k1};
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet, VecDeque};

#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
pub struct AEAD {
    pub ciphertext: Vec<u8>,
    pub tag: Vec<u8>,
}

pub fn aes_encrypt(key: &[u8], plaintext: &[u8]) -> Outcome<AEAD> {
    let mut full_length_key: [u8; 32] = [0; 32];
    full_length_key[(32 - key.len())..].copy_from_slice(key); // pad key with zeros

    let aes_key = aes_gcm::Key::from_slice(full_length_key.as_slice());
    let cipher = Aes256Gcm::new(aes_key);

    let mut _buf = [0u8; 12];
    let nonce = {
        OsRng.fill_bytes(&mut _buf); // provided by Rng trait
        Nonce::from_slice(_buf.as_slice())
    };

    // reserve for later changes when a non-empty aad could be imported
    let aad: Vec<u8> = std::iter::repeat(0).take(16).collect();
    let payload = Payload {
        msg: plaintext,
        aad: aad.as_slice(),
    };

    let ciphertext = cipher
        .encrypt(nonce, payload)
        .catch("AesGcmException", "")?;

    Ok(AEAD {
        ciphertext,
        tag: nonce.to_vec(),
    })
}

pub fn aes_decrypt(key: &[u8], aead_pack: &AEAD) -> Outcome<Vec<u8>> {
    let mut full_length_key: [u8; 32] = [0; 32];
    full_length_key[(32 - key.len())..].copy_from_slice(key); // Pad key with zeros

    let aes_key = aes_gcm::Key::from_slice(full_length_key.as_slice());
    let nonce = Nonce::from_slice(&aead_pack.tag);
    let gcm = Aes256Gcm::new(aes_key);

    // reserve for later changes when a non-empty aad could be imported
    let aad: Vec<u8> = std::iter::repeat(0).take(16).collect();
    let payload = Payload {
        msg: aead_pack.ciphertext.as_slice(),
        aad: aad.as_slice(),
    };

    // NOTE: no error reported but return a value NONE when decrypt key is wrong
    let out = gcm.decrypt(nonce, payload).catch("AesGcmException", "")?;
    Ok(out)
}
pub fn scalar_split(
    x: &Scalar<Secp256k1>,
    members: &HashSet<u16>,
) -> HashMap<u16, Scalar<Secp256k1>> {
    let mut res = HashMap::new();
    let mut members: VecDeque<u16> = members.iter().cloned().collect();
    while members.len() > 1 {
        let member_id = members.pop_front().unwrap();
        res.insert(member_id, Scalar::<Secp256k1>::random());
    }
    let member_id = members.pop_front().unwrap();
    let partial_sum: Scalar<Secp256k1> = res.values().sum();
    res.insert(member_id, x - partial_sum);
    res
}
