//! This is a modified version of `gg18_keygen_client.rs` of Kzen Networks' implementation of GG18 signing:
//! https://github.com/ZenGo-X/multi-party-ecdsa/blob/master/examples/gg18_sign_client.rs
//!

use curv::{
    arithmetic::{BasicOps, Converter, Modulo},
    cryptographic_primitives::{
        proofs::{sigma_correct_homomorphic_elgamal_enc::HomoELGamalProof, sigma_dlog::DLogProof},
        secret_sharing::feldman_vss::VerifiableSS,
    },
    elliptic::curves::{secp256_k1::Secp256k1, Point, Scalar},
    BigInt,
};
use sha2::Sha256;
use svarog_grpc::protogen::svarog::{Signature, TxHash};
use tonic::async_trait;
use xuanmi_base_support::*;

use super::*;
use crate::{MpcMember, util::*};

#[async_trait]
pub trait AlgoSign {
    async fn algo_sign(&self, keystore: &KeyStore, to_sign: &[TxHash]) -> Outcome<Vec<Signature>>;
}

#[async_trait]
impl AlgoSign for MpcMember {
    async fn algo_sign(&self, keystore: &KeyStore, to_sign: &[TxHash]) -> Outcome<Vec<Signature>> {
        let chain_code: [u8; 32] = keystore.chain_code.clone();
        let y_sum: Point<Secp256k1> = Point::from_bytes(&keystore.attr_root_pk(true)).catch_()?;
        let tx_hash_batch: Vec<Vec<u8>> = to_sign
            .iter()
            .map(|tx_hash| tx_hash.tx_hash.clone())
            .collect();
        let derv_path_batch: Vec<String> = to_sign
            .iter()
            .map(|tx_hash| tx_hash.derive_path.clone())
            .collect();
        let (tweak_sk_batch, derv_pk_batch) = {
            let mut tweak_sk_batch = Vec::with_capacity(to_sign.len());
            let mut derv_pk_batch = Vec::with_capacity(to_sign.len());
            for derive in &derv_path_batch {
                if derive.is_empty() {
                    tweak_sk_batch.push(Scalar::<Secp256k1>::zero());
                    derv_pk_batch.push(y_sum.clone());
                } else {
                    let (tweak_sk, derv_pk) =
                        algo_get_hd_key(derive, &y_sum, &chain_code).catch_()?;
                    tweak_sk_batch.push(tweak_sk);
                    derv_pk_batch.push(derv_pk);
                }
            }
            (tweak_sk_batch, derv_pk_batch)
        };

        let my_id = self.attr_member_id();
        let my_group_id = self.attr_group_id();
        let mut signatures = Vec::with_capacity(to_sign.len());

        let mut my_vss_outer_batch = Vec::with_capacity(to_sign.len());
        for tweak_sk in tweak_sk_batch.iter() {
            let mut my_vss_outer = keystore.vss_outer_vec.get(&my_id).ifnone_()?.clone();
            my_vss_outer.commitments[0] =
                my_vss_outer.commitments[0].clone() + Point::generator() * tweak_sk;
            my_vss_outer_batch.push(my_vss_outer);
        }

        Ok(signatures)
    }
}
 
struct VssOuterVecView {
    vss_outer_vec: SparseVec<VerifiableSS<Secp256k1>>,
    vss_outer_tweak: Vec<Scalar<Secp256k1>>,
    my_id: usize,
}

impl VssOuterVecView {
    
}