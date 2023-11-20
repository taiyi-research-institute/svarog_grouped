use curv::{
    arithmetic::{BasicOps, Converter, Modulo},
    cryptographic_primitives::{
        proofs::{sigma_correct_homomorphic_elgamal_enc::HomoELGamalProof, sigma_dlog::DLogProof},
        secret_sharing::feldman_vss::VerifiableSS,
    },
    elliptic::curves::{secp256_k1::Secp256k1, Point, Scalar},
    BigInt,
};
use gg18_kzen::{gg_2018::*, mta::*};
use paillier::*;

use bip32::ChainCode;
use super::hd::algo_get_hd_key;
use crate::prelude::*;
use crate::algo::mta::range_proofs::ZkpPublicSetup;

pub type Pk = Point<Secp256k1>;
pub type PkRespT = AnyhowResult<Pk>; // derived path and pubkey

/// Fetch and compute the derived public key from root pubkey and chaincode.
pub fn algo_pubkey(
    keystore: &str,
    dpath: &str,
) -> AnyhowResult<Pk> {
    let (_, _, _, _, _, root_pk, chaincode, _, _, _,): (
        Keys, SharedKeys, u16, (Vec<VerifiableSS<Secp256k1>>, Vec<VerifiableSS<Secp256k1>>),
        Vec<EncryptionKey>, Point<Secp256k1>, String, u16, HashMap<u16, Vec<u16>>, ZkpPublicSetup,
    ) = crate::ut::json_to_obj(keystore)?;
    let chaincode: [u8; 32] = match hex::decode(chaincode) {
        Ok(u8vec) => match u8vec.as_slice().try_into() {
            Ok(arr) => arr,
            Err(_e) => bail!("The chaincode part of keysfile is not 128 bit."),
        },
        Err(_e) => bail!("The chaincode part of keysfile is not a valid hex-string."),
    };
    if !dpath.is_empty() {
        match algo_get_hd_key(&dpath, &root_pk, &chaincode) {
            Ok((_, derived_pk)) => { 
                return Ok(derived_pk); 
            },
            Err(e) => { return Err(e); },
        }
    } else {
        return Ok(root_pk.clone());
    }
}
