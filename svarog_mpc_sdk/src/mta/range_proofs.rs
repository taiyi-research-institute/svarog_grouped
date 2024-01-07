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

use super::{dlog_proof::DlogProof, nizk_rsa::RsaVecM2, sampling::sample_generator_of_rsa_group};
use crate::{assert_throw, exception::*, mta::nizk_rsa};
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
use zeroize::Zeroize;
use zk_paillier::zkproofs::DLogStatement;

pub const DEFAULT_GROUP_ORDER_BIT_LENGTH: usize = 2048;
pub const DEFAULT_SAFE_PRIME_BIT_LENGTH: usize = DEFAULT_GROUP_ORDER_BIT_LENGTH / 2;

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
    pub n_tilde_proof: RsaVecM2,
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
    pub fn random(group_order_bit_length: usize) -> Outcome<Self> {
        let bit_length = group_order_bit_length / 2;

        // Fujisaki-Okamoto commitment scheme setup
        let One = &BigInt::one();

        // // safe prime generation from crate::primes.rs
        // let p = super::primes::sample_safe_prime(bit_length);
        // let q = super::primes::sample_safe_prime(bit_length);

        // better alternative to safe prime generation from Crate kzen_paillier
        let p = BigInt::sample_safe_prime(bit_length);
        let q = BigInt::sample_safe_prime(bit_length);

        let b0 = loop {
            let b0 = sample_generator_of_rsa_group(&p, &q).catch_()?;
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

        let ret = Self {
            p,
            q,
            alpha,
            N_tilde,
            h1: b0,
            h2: b1,
        };
        Ok(ret)
    }

    #[cfg(test)]
    pub(crate) fn phi(&self) -> BigInt {
        let One = &BigInt::one();
        (&self.p - One) * (&self.q - One)
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
        let One = &BigInt::one();
        let mut phi = (&setup.p - One) * (&setup.q - One);
        let inv_alpha = BigInt::mod_inv(&setup.alpha, &phi).ifnone_()?; // already checked in the constructor
        let inv_n_tilde = BigInt::mod_inv(&setup.N_tilde, &phi).ifnone_()?;
        let n_tilde_proof: RsaVecM2 =
            Self::n_proof(&setup.N_tilde, &setup.p, &setup.q, &inv_n_tilde).catch_()?;
        let max_secret_length = phi.bit_length() as u32;
        phi.zeroize();

        let ret = Self {
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
        };
        Ok(ret)
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
        proof.verify(N_tilde, h1, h2).catch_()?;
        Ok(())
    }

    /// generates non-interactive proof of correctness of RSA modulus
    pub fn n_proof(N_tilde: &BigInt, p: &BigInt, q: &BigInt, exp: &BigInt) -> Outcome<RsaVecM2> {
        assert_throw!(*N_tilde == p * q);
        let rho_vec = nizk_rsa::get_rho_vec(&N_tilde).catch_()?;

        let mut ret = Vec::with_capacity(nizk_rsa::M2);
        for rho in rho_vec {
            let x = BigInt::mod_pow(&rho, exp, N_tilde);
            ret.push(x);
        }
        Ok(ret.try_into().unwrap())
    }

    pub fn verify_n_proof(N_tilde: &BigInt, proof: &RsaVecM2) -> Outcome<()> {
        assert_throw!(proof.len() == nizk_rsa::M2, "wrong length of proof vector");
        assert_throw!(
            N_tilde.bit_length() >= nizk_rsa::N_MIN_SIZE,
            "modulus too small"
        );
        nizk_rsa::check_divisibility(N_tilde).catch("", "N_tilde has a small prime factor")?;

        let zero = BigInt::zero();
        let iter_proof = proof.iter();
        let rho_vec = nizk_rsa::get_rho_vec(&N_tilde).catch_()?;
        let iter_rho = rho_vec.iter();
        for (sigma, rho) in iter_proof.zip(iter_rho) {
            assert_throw!(*sigma > zero, "sigma is negative");
            assert_throw!(
                rho == &BigInt::mod_pow(&sigma, N_tilde, N_tilde),
                "rho is not n-th root of sigma"
            );
        }

        Ok(())
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
    ) -> Outcome<()> {
        let N = &alice_ek.n;
        let NN = &alice_ek.nn;
        let N_tilde = &bob_dlog_statement.N;
        let h1 = &bob_dlog_statement.g;
        let h2 = &bob_dlog_statement.ni;
        let Gen = alice_ek.n.borrow() + 1;

        let s1_not_exceed_cubicsquare_of_q = self.s1 <= Scalar::<Secp256k1>::group_order().pow(3);
        assert_throw!(s1_not_exceed_cubicsquare_of_q);
        let z_e_inv =
            BigInt::mod_inv(&BigInt::mod_pow(&self.z, &self.e, N_tilde), N_tilde).ifnone_()?;

        let w = {
            let mut w = BigInt::mod_pow(h1, &self.s1, N_tilde);
            w = w * BigInt::mod_pow(h2, &self.s2, N_tilde);
            w = w * z_e_inv;
            w = w % N_tilde;
            w
        };
        let gs1 = (self.s1.borrow() * N + 1) % NN;
        let cipher_POWe_inv = {
            let x = BigInt::mod_pow(cipher, &self.e, NN);
            let inv = BigInt::mod_inv(&x, NN);
            inv.ifnone_()?
        };
        let u = {
            let mut u = BigInt::mod_pow(&self.s, N, NN);
            u = gs1 * u;
            u = u * cipher_POWe_inv;
            u = u % NN;
            u
        };
        let e = Sha256::new()
            .chain_bigint(N)
            .chain_bigint(&Gen)
            .chain_bigint(cipher)
            .chain_bigint(&self.z)
            .chain_bigint(&u)
            .chain_bigint(&w)
            .result_bigint();

        assert_throw!(e == self.e);

        Ok(())
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
        let z = {
            let mut z = BigInt::mod_pow(h1, &b_bn, N_tilde);
            z = z * BigInt::mod_pow(h2, &ro, N_tilde);
            z % N_tilde
        };
        let z_prim = {
            let mut z_prim = BigInt::mod_pow(h1, &alpha, N_tilde);
            z_prim = z_prim * BigInt::mod_pow(h2, &ro_prim, N_tilde);
            z_prim % N_tilde
        };
        let t = {
            let mut t = BigInt::mod_pow(h1, beta_prim, N_tilde);
            t = t * BigInt::mod_pow(h2, &sigma, N_tilde);
            t % N_tilde
        };
        let w = {
            let mut w: BigInt = BigInt::mod_pow(h1, &gamma, N_tilde);
            w = w * BigInt::mod_pow(h2, &tau, N_tilde);
            w % N_tilde
        };
        let v = {
            let mut v = BigInt::mod_pow(a_encrypted, &alpha, &alice_ek.nn);
            v = v * (gamma.borrow() * &alice_ek.n + 1);
            v = v * BigInt::mod_pow(&beta, &alice_ek.n, &alice_ek.nn);
            v % &alice_ek.nn
        };
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
    ) -> Outcome<()> {
        let N = &alice_ek.n;
        let NN = &alice_ek.nn;
        let N_tilde = &alice_dlog_statement.N;
        let h1 = &alice_dlog_statement.g;
        let h2 = &alice_dlog_statement.ni;

        let s1_no_exceed_p_pow3 = self.s1 <= Scalar::<Secp256k1>::group_order().pow(3);
        assert_throw!(s1_no_exceed_p_pow3);

        let z_e_inv =
            BigInt::mod_inv(&BigInt::mod_pow(&self.z, &self.e, N_tilde), N_tilde).ifnone_()?;
        let z_prim = {
            let mut z_prim = BigInt::mod_pow(h1, &self.s1, N_tilde);
            z_prim = z_prim * BigInt::mod_pow(h2, &self.s2, N_tilde);
            z_prim = z_prim * z_e_inv;
            z_prim % N_tilde
        };
        let mta_e_inv = {
            let mta_powe = BigInt::mod_pow(mta_avc_out, &self.e, NN);
            BigInt::mod_inv(&mta_powe, NN).ifnone_()?
        };
        let v = {
            let mut v = BigInt::mod_pow(a_enc, &self.s1, NN);
            v = v * BigInt::mod_pow(&self.s, N, NN);
            v = v * (&self.t1 * N + 1);
            v = v * mta_e_inv;
            v % NN
        };
        let t_e_inv = {
            let t_powe = BigInt::mod_pow(&self.t, &self.e, N_tilde);
            BigInt::mod_inv(&t_powe, N_tilde).ifnone_()?
        };
        let w = {
            let mut w = BigInt::mod_pow(h1, &self.t1, N_tilde);
            w = w * BigInt::mod_pow(h2, &self.t2, N_tilde);
            w = w * t_e_inv;
            w % N_tilde
        };

        let Gen = &alice_ek.n + 1;
        let mut e = Sha256::new()
            .chain_bigint(&alice_ek.n)
            .chain_bigint(&Gen)
            .chain_bigint(a_enc)
            .chain_bigint(mta_avc_out)
            .chain_bigint(&self.z)
            .chain_bigint(&z_prim)
            .chain_bigint(&self.t)
            .chain_bigint(&v)
            .chain_bigint(&w);
        if let Some(check) = check {
            let X_x_coor = check.X.x_coord().unwrap();
            let X_y_coor = check.X.y_coord().unwrap();
            let u_x_coor = check.u.x_coord().unwrap();
            let u_y_coor = check.u.y_coord().unwrap();
            e = e
                .chain_bigint(&X_x_coor)
                .chain_bigint(&X_y_coor)
                .chain_bigint(&u_x_coor)
                .chain_bigint(&u_y_coor);
        }
        let e: BigInt = e.result_bigint();
        assert_throw!(e == self.e);

        Ok(())
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

        let mut e = Sha256::new()
            .chain_bigint(&alice_ek.n)
            .chain_bigint(&Gen)
            .chain_bigint(a_encrypted)
            .chain_bigint(mta_encrypted)
            .chain_bigint(&round1.z)
            .chain_bigint(&round1.z_prim)
            .chain_bigint(&round1.t)
            .chain_bigint(&round1.v)
            .chain_bigint(&round1.w);
        let mut check_u = None;
        if check {
            let (X, u) = {
                let ec_gen = Point::generator();
                let alpha = Scalar::<Secp256k1>::from(&round1.alpha);
                (ec_gen * b, ec_gen * alpha)
            };
            check_u = Some(u.clone());
            let X_x_coor = X.x_coord().unwrap();
            let X_y_coor = X.y_coord().unwrap();
            let u_x_coor = u.x_coord().unwrap();
            let u_y_coor = u.y_coord().unwrap();
            e = e
                .chain_bigint(&X_x_coor)
                .chain_bigint(&X_y_coor)
                .chain_bigint(&u_x_coor)
                .chain_bigint(&u_y_coor);
        }
        let e: BigInt = e.result_bigint();

        let round2 = BobZkpRound2::from(alice_ek, &round1, &e, b, beta_prim, r);
        let bob_proof = BobProof {
            t: round1.t.clone(),
            z: round1.z.clone(),
            e,
            s: round2.s,
            s1: round2.s1,
            s2: round2.s2,
            t1: round2.t1,
            t2: round2.t2,
        };
        (bob_proof, check_u)
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
    ) -> Outcome<()> {
        // check basic proof first
        self.proof
            .verify(
                a_enc,
                mta_avc_out,
                alice_ek,
                alice_dlog_statement,
                Some(&BobCheck {
                    u: self.u.clone(),
                    X: X.clone(),
                }),
            )
            .catch_()?;

        // fiddle with EC points
        let (x1, x2) = {
            let ec_gen = Point::generator();
            let s1 = Scalar::<Secp256k1>::from(&self.proof.s1);
            let e = Scalar::<Secp256k1>::from(&self.proof.e);
            let x1 = ec_gen * s1;
            let x2 = (X * &e) + &self.u;
            (x1, x2)
        };
        assert_throw!(x1 == x2);

        Ok(())
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
        alice_proof.verify(&cipher, &ek, &dlog_statement).unwrap();
    }

    #[test]
    fn bob_zkp() {
        let (dlog_statement, ek, _) = generate_init();
        for _outer in 0..5 {
            let alice_public_key = &ek;
            for _inner in 0..5 {
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
                bob_proof
                    .verify(
                        &encrypted_a,
                        &mta_out.0.clone().into_owned(),
                        alice_public_key,
                        &dlog_statement,
                        None,
                    )
                    .unwrap();

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
                bob_proof
                    .verify(
                        &encrypted_a,
                        &mta_out.0.clone().into_owned(),
                        alice_public_key,
                        &dlog_statement,
                        &X,
                    )
                    .unwrap();
            }
        }
    }
}
