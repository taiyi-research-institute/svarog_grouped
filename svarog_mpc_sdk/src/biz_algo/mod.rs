#![allow(non_snake_case)]
/*
    This is a modified version of `party_i.rs` in Kzen Networks' Multi-party ECDSA library
    (https://github.com/KZen-networks/multi-party-ecdsa/src/protocols/multi_party_ecdsa/gg_2018/party_i.rs)
*/

/*
    Multi-party ECDSA

    Copyright 2018 by Kzen Networks

    This file is part of Multi-party ECDSA library
    (https://github.com/KZen-networks/multi-party-ecdsa)

    Multi-party ECDSA is free software: you can redistribute
    it and/or modify it under the terms of the GNU General Public
    License as published by the Free Software Foundation, either
    version 3 of the License, or (at your option) any later version.

    @license GPL-3.0+ <https://github.com/KZen-networks/multi-party-ecdsa/blob/master/LICENSE>
*/

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

use crate::exception::*;
use aes_gcm::{
    aead::{Aead, NewAead, Payload},
    Aes256Gcm, Nonce,
};
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};

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
