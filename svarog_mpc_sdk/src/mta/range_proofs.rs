#![allow(non_snake_case)]

//! This file is a modified version of Kzen Networks' range proofs implementation:
//! https://github.com/ZenGo-X/multi-party-ecdsa/blob/master/src/utilities/mta/range_proofs.rs
//! which was first modified from ING bank's implementation.
//! Noted that `gamma` is now sampled from [0;q^7] rather than [0;q^2 * N] according to the paper (2021 version)
//!
//! This file is a modified version of ING bank's range proofs implementation:
//! https://github.com/ing-bank/threshold-signatures/blob/master/src/algorithms/zkp.rs
//!
//! Zero knowledge range proofs for MtA protocol are implemented here.
//! Formal description can be found in Appendix A of https://eprint.iacr.org/2019/114.pdf
//! There are some deviations from the original specification:
//! 1) In Bob's proofs `gamma` is sampled from `[0;q^2 * N]` and `tau` from `[0;q^3 * N_tilde]`.
//! 2) A non-interactive version is implemented, with challenge `e` computed via Fiat-Shamir.

use curv::{
    arithmetic::traits::{Samplable, *},
    cryptographic_primitives::hashing::{Digest, DigestExt},
    elliptic::curves::{secp256_k1::Secp256k1, Point, Scalar},
    BigInt,
};
use paillier::{EncryptionKey, PrimeSampable, Randomness};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::borrow::Borrow;
use xuanmi_base_support::*;
use zeroize::Zeroize;
use zk_paillier::zkproofs::DLogStatement;

use super::{dlog_proof::DlogProof, nizk_rsa};

pub const DEFAULT_GROUP_ORDER_BIT_LENGTH: usize = 2048;
pub const DEFAULT_SAFE_PRIME_BIT_LENGTH: usize = DEFAULT_GROUP_ORDER_BIT_LENGTH / 2;

// #[derive(Debug, Error)]
// #[error("Zkp setup verification error: {0}")]
// pub struct ZkpSetupVerificationError(String);

/// Zero knowledge range proof setup.
/// It has to be created before using range proofs
/// The setup consist of following private values  $`p`$ and $`q`$ primes, $` \: \alpha \in \mathbb{Z}_{\tilde{N}}^{\star} `$
/// and public values $` \tilde{N} , h_{1}, h_{2}  `$
/// where $` \tilde{N} = \tilde{P} * \tilde{Q} ,\: \tilde{P} = 2*p + 1 ,\: \tilde{Q} = 2*q + 1, \: h_{1} \in \mathbb{Z}_{\tilde{N}}^{\star}, \: h_{2} = h_{1}^{\alpha}  `$
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZkpSetup {
    p: BigInt,
    q: BigInt,
    alpha: BigInt,
    pub N_tilde: BigInt,
    pub h1: BigInt,
    pub h2: BigInt,
}

/// Zeroes the memory occupied by the struct
impl Zeroize for ZkpSetup {
    fn zeroize(&mut self) {
        self.p.zeroize();
        self.q.zeroize();
        self.alpha.zeroize();
        self.N_tilde.zeroize();
        self.h1.zeroize();
        self.h2.zeroize();
    }
}

/// Zeroes the memory occupied by the struct
impl Drop for ZkpSetup {
    fn drop(&mut self) {
        self.zeroize();
    }
}

/// Zero knowledge range proof setup, public part only.
/// It has to be shared with other parties before using range proofs.
/// Contains public fields of the setup and Dlog proof of the correctness
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZkpPublicSetup {
    pub N_tilde: BigInt,
    pub h1: BigInt,
    pub h2: BigInt,
    pub dlog_proof: DlogProof,
    pub inv_dlog_proof: DlogProof,
    pub n_tilde_proof: Vec<BigInt>,
}

/// The non-interactive proof of correctness of zero knowledge range proof setup.
/// Uses Schnorr's proof of knowing the discrete logarithm.
/// Needs to be shared with each party along with the setup itself
#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
pub struct ZkpSetupProof {
    pub V: BigInt,
    pub challenge: BigInt,
    pub r: BigInt,
}

impl ZkpSetup {
    /// Generates new zero knowledge range proof setup.
    /// Uses Fujisaki - Okamoto bit commitment scheme, "Statistical zero knowledge protocols to prove modular polynomial relations"
    pub fn random(group_order_bit_length: usize) -> Self {
        use crate::mta::sampling::sample_generator_of_rsa_group;
        let bit_length = group_order_bit_length / 2;

        // Fujisaki-Okamoto commitment scheme setup
        let One = &BigInt::one();

        // // safe prime generation from crate::primes.rs
        // let p = super::primes::sample_safe_prime(bit_length);
        // let q = super::primes::sample_safe_prime(bit_length);

        // better alternative to safe prime generation from Crate kzen_paillier
        let p = BigInt::sample_safe_prime(bit_length);
        let q = BigInt::sample_safe_prime(bit_length);

        // // hardcoded for testing only
        // let p_str = "228887768202115306593565368808592820237599162302790891136048210859700463168536347859891577256113351052877496083355171100730194866748253815965189419009447097559570228359696848947525043155201021818338978912026318620560515741646245029449014851622920104903693275061770186381936314279545231142191270874232085907767";
        // let q_str = "117856446678054745990472425711910435781072493645370951370838434118297543700237047098408115413013509045457837730951824888879845476417708877498761573788305597382464330724492497557874169226512497782816524324645552982006382507540861532391525971690563763493899740442298815254333451503908665030820892318703151902127";
        // let p = BigInt::from_str_radix(p_str, 10).unwrap();
        // let q = BigInt::from_str_radix(q_str, 10).unwrap();

        let b0 = loop {
            let b0 = sample_generator_of_rsa_group(&p, &q);
            if b0 != *One {
                break b0;
            }
        };

        let N_tilde = &p * &q;
        let mut phi = (&p - One) * (&q - One);
        let alpha = loop {
            let alpha = BigInt::strict_sample_range(&BigInt::from(1), &(phi.borrow() / 4));
            if BigInt::mod_inv(&alpha, &phi).is_some() {
                break alpha;
            }
        };
        phi.zeroize();
        let b1 = BigInt::mod_pow(&b0, &alpha, &N_tilde);

        Self {
            p,
            q,
            alpha,
            N_tilde,
            h1: b0,
            h2: b1,
        }
    }

    #[cfg(test)]
    pub(crate) fn phi(&self) -> BigInt {
        let One = &BigInt::one();
        (self.p.borrow() - One) * (self.q.borrow() - One)
    }

    #[cfg(test)]
    pub(crate) fn alpha(&self) -> &BigInt {
        &self.alpha
    }
}

impl ZkpPublicSetup {
    const DLOG_PROOF_SECURITY_PARAMETER: u32 = 128;
    ///  Creates new public setup from private one
    ///
    ///  Creates new public setup and generates proof of knowledge of $` \alpha , \alpha^{-1} `$
    /// and proof of $` gcd(\tilde{N}, phi(\tilde{N} ) = 1 `$
    pub fn from_private_zkp_setup(setup: &ZkpSetup) -> Outcome<Self> {
        let err = "InvalidZkpSetup";
        let One = &BigInt::one();
        let mut phi = (&setup.p - One) * (&setup.q - One);
        let inv_alpha =
            BigInt::mod_inv(&setup.alpha, &phi).ifnone(err, "alpha must be invertible")?; // already checked in the constructor
        let inv_n_tilde =
            BigInt::mod_inv(&setup.N_tilde, &phi).ifnone(err, "N-tilde is no invertible")?;
        let n_tilde_proof =
            Self::n_proof(&setup.N_tilde, &setup.p, &setup.q, &inv_n_tilde).catch_()?;
        let max_secret_length = phi.bit_length() as u32;
        phi.zeroize();

        Ok(Self {
            N_tilde: setup.N_tilde.clone(),
            h1: setup.h1.clone(),
            h2: setup.h2.clone(),
            dlog_proof: DlogProof::create(
                &setup.N_tilde,
                &setup.h1,
                &setup.h2,
                &setup.alpha,
                max_secret_length,
                Self::DLOG_PROOF_SECURITY_PARAMETER,
            ),
            inv_dlog_proof: DlogProof::create(
                &setup.N_tilde,
                &setup.h2,
                &setup.h1,
                &inv_alpha,
                max_secret_length,
                Self::DLOG_PROOF_SECURITY_PARAMETER,
            ),
            n_tilde_proof,
        })
    }

    /// verifies public setup
    ///
    /// verifies public setup using classic Schnorr's proof
    pub fn verify(&self) -> Outcome<()> {
        Self::verify_n_proof(&self.N_tilde, &self.n_tilde_proof).catch_()?;
        let One = BigInt::one();
        assert_throw!(self.h1 != One);
        assert_throw!(self.h2 != One);
        Self::verify_dlog_proof(&self.N_tilde, &self.h1, &self.h2, &self.dlog_proof).catch_()?;
        Self::verify_dlog_proof(&self.N_tilde, &self.h2, &self.h1, &self.inv_dlog_proof)
            .catch_()?;

        Ok(())
    }

    pub fn verify_dlog_proof(
        N_tilde: &BigInt,
        h1: &BigInt,
        h2: &BigInt,
        proof: &DlogProof,
    ) -> Outcome<()> {
        let proof_verified = proof.verify(N_tilde, h1, h2);
        assert_throw!(proof_verified, "Dlog proof failed");
        Ok(())
    }

    /// generates non-interactive proof of correctness of RSA modulus
    pub fn n_proof(N_tilde: &BigInt, p: &BigInt, q: &BigInt, exp: &BigInt) -> Outcome<Vec<BigInt>> {
        assert_throw!(*N_tilde == p * q);

        let ret = nizk_rsa::get_rho_vec(&N_tilde)
            .into_iter()
            .map(|rho| BigInt::mod_pow(&rho, exp, N_tilde))
            .collect();
        Ok(ret)
    }

    pub fn verify_n_proof(N_tilde: &BigInt, proof: &[BigInt]) -> Outcome<()> {
        let err = "ZkpSetupVerificationError";
        assert_throw!(
            proof.len() == nizk_rsa::M2,
            err,
            "wrong length of proof vector"
        );
        assert_throw!(
            N_tilde.bit_length() >= nizk_rsa::N_MIN_SIZE,
            err,
            "modulus too small"
        );

        let zero = BigInt::zero();
        nizk_rsa::check_divisibility(N_tilde)
            .catch(err, "modulus divisible by a small prime(s)")?;

        let x = proof
            .iter()
            .zip(nizk_rsa::get_rho_vec(&N_tilde))
            .try_for_each(|(sigma, rho)| -> Outcome<()> {
                assert_throw!(sigma > &zero, err, "negative sigma");
                let nth_root_valid = rho == BigInt::mod_pow(sigma, N_tilde, N_tilde);
                assert_throw!(nth_root_valid, err, "invalid n-th root");
                Ok(())
            });
        x
    }
}

impl Zeroize for ZkpPublicSetup {
    fn zeroize(&mut self) {
        self.N_tilde.zeroize();
        self.h1.zeroize();
        self.h2.zeroize();
    }
}

/// Represents the first round of the interactive version of the proof
#[derive(Zeroize)]
#[zeroize(drop)]
struct AliceZkpRound1 {
    alpha: BigInt,
    beta: BigInt,
    gamma: BigInt,
    ro: BigInt,
    z: BigInt,
    u: BigInt,
    w: BigInt,
}

impl AliceZkpRound1 {
    fn from(
        alice_ek: &EncryptionKey,
        bob_dlog_statement: &DLogStatement,
        a: &BigInt,
        q: &BigInt,
    ) -> Self {
        let h1 = &bob_dlog_statement.g;
        let h2 = &bob_dlog_statement.ni;
        let N_tilde = &bob_dlog_statement.N;
        let alpha = BigInt::sample_below(&q.pow(3));
        let beta = BigInt::from_paillier_key(alice_ek);
        let gamma = BigInt::sample_below(&(q.pow(3) * N_tilde));
        let ro = BigInt::sample_below(&(q * N_tilde));
        let z = (BigInt::mod_pow(h1, a, N_tilde) * BigInt::mod_pow(h2, &ro, N_tilde)) % N_tilde;
        let u = ((alpha.borrow() * &alice_ek.n + 1)
            * BigInt::mod_pow(&beta, &alice_ek.n, &alice_ek.nn))
            % &alice_ek.nn;
        let w =
            (BigInt::mod_pow(h1, &alpha, N_tilde) * BigInt::mod_pow(h2, &gamma, N_tilde)) % N_tilde;
        Self {
            alpha,
            beta,
            gamma,
            ro,
            z,
            u,
            w,
        }
    }
}

/// Represents the second round of the interactive version of the proof
struct AliceZkpRound2 {
    s: BigInt,
    s1: BigInt,
    s2: BigInt,
}

impl AliceZkpRound2 {
    fn from(
        alice_ek: &EncryptionKey,
        round1: &AliceZkpRound1,
        e: &BigInt,
        a: &BigInt,
        r: &BigInt,
    ) -> Self {
        Self {
            s: (BigInt::mod_pow(r, e, &alice_ek.n) * round1.beta.borrow()) % &alice_ek.n,
            s1: (e * a) + round1.alpha.borrow(),
            s2: (e * round1.ro.borrow()) + round1.gamma.borrow(),
        }
    }
}

/// Alice's proof
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AliceProof {
    z: BigInt,
    e: BigInt,
    s: BigInt,
    s1: BigInt,
    s2: BigInt,
}

impl AliceProof {
    /// verify Alice's proof using the proof and public keys
    pub fn verify(
        &self,
        cipher: &BigInt,
        alice_ek: &EncryptionKey,
        bob_dlog_statement: &DLogStatement,
    ) -> bool {
        let N = &alice_ek.n;
        let NN = &alice_ek.nn;
        let N_tilde = &bob_dlog_statement.N;
        let h1 = &bob_dlog_statement.g;
        let h2 = &bob_dlog_statement.ni;
        let Gen = alice_ek.n.borrow() + 1;

        if self.s1 > Scalar::<Secp256k1>::group_order().pow(3) {
            println!("Error: s1 > q^3!");
            return false;
        }

        let z_e_inv = BigInt::mod_inv(&BigInt::mod_pow(&self.z, &self.e, N_tilde), N_tilde);
        let z_e_inv = match z_e_inv {
            // z must be invertible, yet the check is done here
            None => {
                println!("Error: z^e not invertible!");
                return false;
            }
            Some(c) => c,
        };

        let w = (BigInt::mod_pow(h1, &self.s1, N_tilde)
            * BigInt::mod_pow(h2, &self.s2, N_tilde)
            * z_e_inv)
            % N_tilde;

        let gs1 = (self.s1.borrow() * N + 1) % NN;
        let cipher_e_inv = BigInt::mod_inv(&BigInt::mod_pow(cipher, &self.e, NN), NN);
        let cipher_e_inv = match cipher_e_inv {
            None => {
                println!("Error: cipher^e not invertible!");
                return false;
            }
            Some(c) => c,
        };

        let u = (gs1 * BigInt::mod_pow(&self.s, N, NN) * cipher_e_inv) % NN;

        let e = Sha256::new()
            .chain_bigint(N)
            .chain_bigint(&Gen)
            .chain_bigint(cipher)
            .chain_bigint(&self.z)
            .chain_bigint(&u)
            .chain_bigint(&w)
            .result_bigint();
        if e != self.e {
            println!("Error: e not equal!");
            return false;
        }

        true
    }
    /// Create the proof using Alice's Paillier private keys and public ZKP setup.
    /// Requires randomness used for encrypting Alice's secret a.
    /// It is assumed that secp256k1 curve is used.
    pub fn generate(
        a: &BigInt,
        cipher: &BigInt,
        alice_ek: &EncryptionKey,
        bob_dlog_statement: &DLogStatement,
        r: &BigInt,
    ) -> Self {
        let round1 = AliceZkpRound1::from(
            alice_ek,
            bob_dlog_statement,
            a,
            Scalar::<Secp256k1>::group_order(),
        );

        let Gen = alice_ek.n.borrow() + 1;

        let e = Sha256::new()
            .chain_bigint(&alice_ek.n)
            .chain_bigint(&Gen)
            .chain_bigint(cipher)
            .chain_bigint(&round1.z)
            .chain_bigint(&round1.u)
            .chain_bigint(&round1.w)
            .result_bigint();

        let round2 = AliceZkpRound2::from(alice_ek, &round1, &e, a, r);

        Self {
            z: round1.z.clone(),
            e,
            s: round2.s,
            s1: round2.s1,
            s2: round2.s2,
        }
    }
}

/// Represents first round of the interactive version of the proof
#[derive(Zeroize)]
#[zeroize(drop)]
struct BobZkpRound1 {
    pub alpha: BigInt,
    pub beta: BigInt,
    pub gamma: BigInt,
    pub ro: BigInt,
    pub ro_prim: BigInt,
    pub sigma: BigInt,
    pub tau: BigInt,
    pub z: BigInt,
    pub z_prim: BigInt,
    pub t: BigInt,
    pub w: BigInt,
    pub v: BigInt,
}

impl BobZkpRound1 {
    /// `b` - Bob's secret
    /// `beta_prim`  - randomly chosen in `MtA` by Bob
    /// `a_encrypted` - Alice's secret encrypted by Alice
    fn from(
        alice_ek: &EncryptionKey,
        alice_dlog_statement: &DLogStatement,
        b: &Scalar<Secp256k1>,
        beta_prim: &BigInt,
        a_encrypted: &BigInt, // Enc(ki)
        q: &BigInt,
    ) -> Self {
        let h1 = &alice_dlog_statement.g;
        let h2 = &alice_dlog_statement.ni;
        let N_tilde = &alice_dlog_statement.N;
        let b_bn = b.to_bigint(); // x

        let alpha = BigInt::sample_below(&q.pow(3));
        let beta = BigInt::from_paillier_key(alice_ek);
        // let gamma = BigInt::sample_below(&(q.pow(2) * &alice_ek.n));
        let gamma = BigInt::sample_below(&q.pow(7)); // to comply with the paper
        let ro = BigInt::sample_below(&(q * N_tilde));
        let ro_prim = BigInt::sample_below(&(q.pow(3) * N_tilde));
        let sigma = BigInt::sample_below(&(q * N_tilde));
        let tau = BigInt::sample_below(&(q.pow(3) * N_tilde));
        let z = (BigInt::mod_pow(h1, &b_bn, N_tilde) * BigInt::mod_pow(h2, &ro, N_tilde)) % N_tilde;
        let z_prim = (BigInt::mod_pow(h1, &alpha, N_tilde)
            * BigInt::mod_pow(h2, &ro_prim, N_tilde))
            % N_tilde;
        let t = (BigInt::mod_pow(h1, beta_prim, N_tilde) * BigInt::mod_pow(h2, &sigma, N_tilde))
            % N_tilde;
        let w =
            (BigInt::mod_pow(h1, &gamma, N_tilde) * BigInt::mod_pow(h2, &tau, N_tilde)) % N_tilde;
        let v = (BigInt::mod_pow(a_encrypted, &alpha, &alice_ek.nn)
            * (gamma.borrow() * &alice_ek.n + 1)
            * BigInt::mod_pow(&beta, &alice_ek.n, &alice_ek.nn))
            % &alice_ek.nn;
        Self {
            alpha,
            beta,
            gamma,
            ro,
            ro_prim,
            sigma,
            tau,
            z,
            z_prim,
            t,
            w,
            v,
        }
    }
}

/// represents second round of the interactive version of the proof
struct BobZkpRound2 {
    pub s: BigInt,
    pub s1: BigInt,
    pub s2: BigInt,
    pub t1: BigInt,
    pub t2: BigInt,
}

impl BobZkpRound2 {
    /// `e` - the challenge in interactive ZKP, the hash in non-interactive ZKP
    /// `b` - Bob's secret
    /// `beta_prim` - randomly chosen in `MtA` by Bob
    /// `r` - randomness used by Bob on  Alice's public Paillier key to encrypt `beta_prim` in `MtA`
    fn from(
        alice_ek: &EncryptionKey,
        round1: &BobZkpRound1,
        e: &BigInt,
        b: &Scalar<Secp256k1>,
        beta_prim: &BigInt, // y
        r: &Randomness,
    ) -> Self {
        let b_bn = b.to_bigint(); // x
        Self {
            s: (BigInt::mod_pow(r.0.borrow(), e, &alice_ek.n) * round1.beta.borrow()) % &alice_ek.n,
            s1: (e * b_bn) + round1.alpha.borrow(),
            s2: (e * round1.ro.borrow()) + round1.ro_prim.borrow(),
            t1: (e * beta_prim) + round1.gamma.borrow(),
            t2: (e * round1.sigma.borrow()) + round1.tau.borrow(),
        }
    }
}

/// Additional fields in Bob's proof if MtA is run with check
pub struct BobCheck {
    u: Point<Secp256k1>,
    X: Point<Secp256k1>,
}

/// Bob's regular proof
#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
pub struct BobProof {
    t: BigInt,
    z: BigInt,
    e: BigInt,
    s: BigInt,
    s1: BigInt,
    s2: BigInt,
    t1: BigInt,
    t2: BigInt,
}

#[allow(clippy::too_many_arguments)]
impl BobProof {
    pub fn verify(
        &self,
        a_enc: &BigInt,       // c_1
        mta_avc_out: &BigInt, // c_2
        alice_ek: &EncryptionKey,
        alice_dlog_statement: &DLogStatement,
        check: Option<&BobCheck>,
    ) -> bool {
        let N = &alice_ek.n;
        let NN = &alice_ek.nn;
        let N_tilde = &alice_dlog_statement.N;
        let h1 = &alice_dlog_statement.g;
        let h2 = &alice_dlog_statement.ni;

        if self.s1 > Scalar::<Secp256k1>::group_order().pow(3) {
            println!("Error: s1 > p3!");
            return false;
        }

        let z_e_inv = BigInt::mod_inv(&BigInt::mod_pow(&self.z, &self.e, N_tilde), N_tilde);
        let z_e_inv = match z_e_inv {
            // z must be invertible, yet the check is done here
            None => {
                println!("Error: z_e not invertible!");
                return false;
            }
            Some(c) => c,
        };

        let z_prim = (BigInt::mod_pow(h1, &self.s1, N_tilde)
            * BigInt::mod_pow(h2, &self.s2, N_tilde)
            * z_e_inv)
            % N_tilde;

        let mta_e_inv = BigInt::mod_inv(&BigInt::mod_pow(mta_avc_out, &self.e, NN), NN);
        let mta_e_inv = match mta_e_inv {
            None => {
                println!("Error: mta_e not invertible!");
                return false;
            }
            Some(c) => c,
        };

        let v = (BigInt::mod_pow(a_enc, &self.s1, NN)
            * BigInt::mod_pow(&self.s, N, NN)
            * (self.t1.borrow() * N + 1)
            * mta_e_inv)
            % NN;

        let t_e_inv = BigInt::mod_inv(&BigInt::mod_pow(&self.t, &self.e, N_tilde), N_tilde);
        let t_e_inv = match t_e_inv {
            None => {
                println!("Error: t_e not invertible!");
                return false;
            }
            Some(c) => c,
        };

        let w = (BigInt::mod_pow(h1, &self.t1, N_tilde)
            * BigInt::mod_pow(h2, &self.t2, N_tilde)
            * t_e_inv)
            % N_tilde;

        let Gen = alice_ek.n.borrow() + 1;
        let mut values_to_hash = vec![
            &alice_ek.n,
            &Gen,
            a_enc,
            mta_avc_out,
            &self.z,
            &z_prim,
            &self.t,
            &v,
            &w,
        ];
        let e = match check {
            Some(_) => {
                let X_x_coor = check.unwrap().X.x_coord().unwrap();
                values_to_hash.push(&X_x_coor);
                let X_y_coor = check.unwrap().X.y_coord().unwrap();
                values_to_hash.push(&X_y_coor);
                let u_x_coor = check.unwrap().u.x_coord().unwrap();
                values_to_hash.push(&u_x_coor);
                let u_y_coor = check.unwrap().u.y_coord().unwrap();
                values_to_hash.push(&u_y_coor);
                values_to_hash
                    .into_iter()
                    .fold(Sha256::new(), |acc, b| acc.chain_bigint(b))
                    .result_bigint()
            }
            None => values_to_hash
                .into_iter()
                .fold(Sha256::new(), |acc, b| acc.chain_bigint(b))
                .result_bigint(),
        };

        if e != self.e {
            println!("Error: e not equal!"); // here again!
            return false;
        }

        true
    }

    pub fn generate(
        a_encrypted: &BigInt,   // c_1
        mta_encrypted: &BigInt, // c_2
        b: &Scalar<Secp256k1>,
        beta_prim: &BigInt,
        alice_ek: &EncryptionKey,
        alice_dlog_statement: &DLogStatement,
        r: &Randomness,
        check: bool,
    ) -> (BobProof, Option<Point<Secp256k1>>) {
        let round1 = BobZkpRound1::from(
            alice_ek,
            alice_dlog_statement,
            b,
            beta_prim,
            a_encrypted,
            Scalar::<Secp256k1>::group_order(),
        );

        let Gen = alice_ek.n.borrow() + 1;
        let mut values_to_hash = vec![
            &alice_ek.n,
            &Gen,
            a_encrypted,
            mta_encrypted,
            &round1.z,
            &round1.z_prim,
            &round1.t,
            &round1.v,
            &round1.w,
        ];
        let mut check_u = None;
        let e = if check {
            let (X, u) = {
                let ec_gen = Point::generator();
                let alpha = Scalar::<Secp256k1>::from(&round1.alpha);
                (ec_gen * b, ec_gen * alpha)
            };
            check_u = Some(u.clone());
            let X_x_coor = X.x_coord().unwrap();
            values_to_hash.push(&X_x_coor);
            let X_y_coor = X.y_coord().unwrap();
            values_to_hash.push(&X_y_coor);
            let u_x_coor = u.x_coord().unwrap();
            values_to_hash.push(&u_x_coor);
            let u_y_coor = u.y_coord().unwrap();
            values_to_hash.push(&u_y_coor);
            values_to_hash
                .into_iter()
                .fold(Sha256::new(), |acc, b| acc.chain_bigint(b))
                .result_bigint()
        } else {
            values_to_hash
                .into_iter()
                .fold(Sha256::new(), |acc, b| acc.chain_bigint(b))
                .result_bigint()
        };

        let round2 = BobZkpRound2::from(alice_ek, &round1, &e, b, beta_prim, r);

        (
            BobProof {
                t: round1.t.clone(),
                z: round1.z.clone(),
                e,
                s: round2.s,
                s1: round2.s1,
                s2: round2.s2,
                t1: round2.t1,
                t2: round2.t2,
            },
            check_u,
        )
    }
}

/// Bob's extended proof, adds the knowledge of $`B = g^b \in \mathcal{G}`$
#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
pub struct BobProofExt {
    proof: BobProof,
    u: Point<Secp256k1>,
}

#[allow(clippy::too_many_arguments)]
impl BobProofExt {
    pub fn verify(
        &self,
        a_enc: &BigInt,
        mta_avc_out: &BigInt,
        alice_ek: &EncryptionKey,
        alice_dlog_statement: &DLogStatement,
        X: &Point<Secp256k1>,
    ) -> bool {
        // check basic proof first
        if !self.proof.verify(
            a_enc,
            mta_avc_out,
            alice_ek,
            alice_dlog_statement,
            Some(&BobCheck {
                u: self.u.clone(),
                X: X.clone(),
            }),
        ) {
            return false;
        }

        // fiddle with EC points
        let (x1, x2) = {
            let ec_gen = Point::generator();
            let s1 = Scalar::<Secp256k1>::from(&self.proof.s1);
            let e = Scalar::<Secp256k1>::from(&self.proof.e);
            (ec_gen * s1, (X * &e) + &self.u)
        };

        if x1 != x2 {
            return false;
        }

        true
    }

    pub fn generate(
        a_encrypted: &BigInt,
        mta_encrypted: &BigInt,
        b: &Scalar<Secp256k1>,
        beta_prim: &BigInt,
        alice_ek: &EncryptionKey,
        alice_dlog_statement: &DLogStatement,
        r: &Randomness,
    ) -> BobProofExt {
        // proving a basic proof (with modified hash)
        let (bob_proof, u) = BobProof::generate(
            a_encrypted,
            mta_encrypted,
            b,
            beta_prim,
            alice_ek,
            alice_dlog_statement,
            r,
            true,
        );

        BobProofExt {
            proof: bob_proof,
            u: u.unwrap(),
        }
    }
}

/// sample random value of an element of a multiplicative group
pub trait SampleFromMultiplicativeGroup {
    fn from_modulo(N: &BigInt) -> BigInt;
    fn from_paillier_key(ek: &EncryptionKey) -> BigInt;
}

impl SampleFromMultiplicativeGroup for BigInt {
    fn from_modulo(N: &BigInt) -> BigInt {
        let One = BigInt::one();
        loop {
            let r = Self::sample_below(N);
            if r.gcd(N) == One {
                return r;
            }
        }
    }

    fn from_paillier_key(ek: &EncryptionKey) -> BigInt {
        Self::from_modulo(ek.n.borrow())
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use paillier::traits::{Encrypt, EncryptWithChosenRandomness, KeyGeneration};
    use paillier::{Add, DecryptionKey, Mul, Paillier, RawCiphertext, RawPlaintext};

    fn generate(
        a_encrypted: &BigInt,
        mta_encrypted: &BigInt,
        b: &Scalar<Secp256k1>,
        beta_prim: &BigInt,
        alice_ek: &EncryptionKey,
        alice_dlog_statement: &DLogStatement,
        r: &Randomness,
    ) -> BobProofExt {
        // proving a basic proof (with modified hash)
        let (bob_proof, u) = BobProof::generate(
            a_encrypted,
            mta_encrypted,
            b,
            beta_prim,
            alice_ek,
            alice_dlog_statement,
            r,
            true,
        );

        BobProofExt {
            proof: bob_proof,
            u: u.unwrap(),
        }
    }

    pub(crate) fn generate_init() -> (DLogStatement, EncryptionKey, DecryptionKey) {
        let (ek_tilde, dk_tilde) = Paillier::keypair().keys();
        let one = BigInt::one();
        let phi = (&dk_tilde.p - &one) * (&dk_tilde.q - &one);
        let h1 = BigInt::sample_below(&ek_tilde.n);
        let (xhi, _) = loop {
            let xhi_ = BigInt::sample_below(&phi);
            match BigInt::mod_inv(&xhi_, &phi) {
                Some(inv) => break (xhi_, inv),
                None => continue,
            }
        };
        let h2 = BigInt::mod_pow(&h1, &xhi, &ek_tilde.n);

        let (ek, dk) = Paillier::keypair().keys();
        let dlog_statement = DLogStatement {
            g: h1,
            ni: h2,
            N: ek_tilde.n,
        };
        (dlog_statement, ek, dk)
    }

    #[test]
    fn alice_zkp() {
        let (dlog_statement, ek, _) = generate_init();

        // Alice's secret value
        let a = Scalar::<Secp256k1>::random().to_bigint();
        let r = BigInt::from_paillier_key(&ek);
        let cipher = Paillier::encrypt_with_chosen_randomness(
            &ek,
            RawPlaintext::from(a.clone()),
            &Randomness::from(&r),
        )
        .0
        .clone()
        .into_owned();

        let alice_proof = AliceProof::generate(&a, &cipher, &ek, &dlog_statement, &r);

        assert!(alice_proof.verify(&cipher, &ek, &dlog_statement));
    }

    #[test]
    fn bob_zkp() {
        let (dlog_statement, ek, _) = generate_init();

        (0..5).for_each(|_| {
            let alice_public_key = &ek;

            // run MtA protocol with different inputs
            (0..5).for_each(|_| {
                // Simulate Alice
                let a = Scalar::<Secp256k1>::random().to_bigint();
                let encrypted_a = Paillier::encrypt(alice_public_key, RawPlaintext::from(a))
                    .0
                    .clone()
                    .into_owned();

                // Bob follows MtA
                let b = Scalar::<Secp256k1>::random();
                // E(a) * b
                let b_times_enc_a = Paillier::mul(
                    alice_public_key,
                    RawCiphertext::from(encrypted_a.clone()),
                    RawPlaintext::from(&b.to_bigint()),
                );
                let beta_prim = BigInt::sample_below(&alice_public_key.n);
                let r = Randomness::sample(alice_public_key);
                let enc_beta_prim = Paillier::encrypt_with_chosen_randomness(
                    alice_public_key,
                    RawPlaintext::from(&beta_prim),
                    &r,
                );

                let mta_out = Paillier::add(alice_public_key, b_times_enc_a, enc_beta_prim);

                let (bob_proof, _) = BobProof::generate(
                    &encrypted_a,
                    &mta_out.0.clone().into_owned(),
                    &b,
                    &beta_prim,
                    alice_public_key,
                    &dlog_statement,
                    &r,
                    false,
                );
                assert!(bob_proof.verify(
                    &encrypted_a,
                    &mta_out.0.clone().into_owned(),
                    alice_public_key,
                    &dlog_statement,
                    None
                ));

                // Bob follows MtAwc
                let ec_gen = Point::generator();
                let X = ec_gen * &b;
                let bob_proof = generate(
                    &encrypted_a,
                    &mta_out.0.clone().into_owned(),
                    &b,
                    &beta_prim,
                    alice_public_key,
                    &dlog_statement,
                    &r,
                );
                assert!(bob_proof.verify(
                    &encrypted_a,
                    &mta_out.0.clone().into_owned(),
                    alice_public_key,
                    &dlog_statement,
                    &X
                ));
            });
        });
    }
}
