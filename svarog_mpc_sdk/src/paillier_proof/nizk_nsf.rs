#![allow(non_snake_case)]
use curv::{
    arithmetic::{
        BasicOps, BitManipulation, Converter, Integer, Modulo, NumberTests, One, Roots, Samplable,
        Zero,
    },
    BigInt,
};
use num_bigint::{BigInt as BN, Sign};
use paillier::DecryptionKey;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha512};
use std::{ops::Neg, vec};
use zk_paillier::zkproofs::DLogStatement;

const L: u32 = 256; // N0 = pq, where -sqrt(N0) * 2^l < p,q < sqrt(N0) * 2^l
const EPSILON: u32 = 512;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NSFProof {
    P: BigInt,
    Q: BigInt,
    A: BigInt,
    B: BigInt,
    T: BigInt,
    sigma: BN,
    z1: BN,
    z2: BN,
    w1: BN,
    w2: BN,
    v: BN,
    salt: String,
}

impl NSFProof {
    pub fn generate(setup: &DLogStatement, N0: &BigInt, dk: &DecryptionKey, salt: &str) -> Self {
        let two = BigInt::from(2);

        let N_tilde = setup.N.clone();
        let s = setup.g.clone();
        let t = setup.ni.clone();
        let sqrt_N0 = N0.sqrt();

        let bound_alpha_beta = &sqrt_N0 * &two.pow(L + EPSILON);
        let bound_mu_nu = &N_tilde * &two.pow(L);
        let bound_sigma = &bound_mu_nu * N0;
        let bound_r = &bound_sigma * &two.pow(EPSILON);
        let bound_x_y = &bound_mu_nu * &two.pow(EPSILON);

        let alpha = BigInt::strict_sample_range(&-&bound_alpha_beta, &bound_alpha_beta);
        let beta = BigInt::strict_sample_range(&-&bound_alpha_beta, &bound_alpha_beta);
        let mu = BigInt::strict_sample_range(&-&bound_mu_nu, &bound_mu_nu);
        let nu = BigInt::strict_sample_range(&-&bound_mu_nu, &bound_mu_nu);
        let sigma = BigInt::strict_sample_range(&-&bound_sigma, &bound_sigma);
        let r = BigInt::strict_sample_range(&-&bound_r, &bound_r);
        let x = BigInt::strict_sample_range(&-&bound_x_y, &bound_x_y);
        let y = BigInt::strict_sample_range(&-&bound_x_y, &bound_x_y);

        let P =
            (mod_any_pow(&s, &dk.p, &N_tilde) * mod_any_pow(&t, &mu, &N_tilde)).modulus(&N_tilde);
        let Q =
            (mod_any_pow(&s, &dk.q, &N_tilde) * mod_any_pow(&t, &nu, &N_tilde)).modulus(&N_tilde);
        let A =
            (mod_any_pow(&s, &alpha, &N_tilde) * mod_any_pow(&t, &x, &N_tilde)).modulus(&N_tilde);
        let B =
            (mod_any_pow(&s, &beta, &N_tilde) * mod_any_pow(&t, &y, &N_tilde)).modulus(&N_tilde);
        let T =
            (mod_any_pow(&Q, &alpha, &N_tilde) * mod_any_pow(&t, &r, &N_tilde)).modulus(&N_tilde);

        let mut hasher = Sha512::new();
        for value in vec![N0, &P, &Q, &A, &B, &T, &sigma] {
            let as_vec = BigInt::to_bytes(value);
            let vec_length = u16::try_from(as_vec.len()).expect("BigInt: bit length too big");
            hasher.update(vec_length.to_le_bytes());
            hasher.update(&as_vec);
        }
        if salt.len() > 0 {
            hasher.update(salt);
        }
        let digest = hasher.finalize();
        let mut e = BigInt::from_bytes(&digest[0..32]);
        if (digest[63] & 0x01) != 0 {
            e = e.neg();
        }

        let sigma_tilde = &sigma - &nu * &dk.p;
        let z1 = &alpha + &e * &dk.p;
        let z2 = &beta + &e * &dk.q;
        let w1 = &x + &e * &mu;
        let w2 = &y + &e * &nu;
        let v = &r + &e * &sigma_tilde;

        Self {
            P,
            Q,
            A,
            B,
            T,
            sigma: to_num_bigint(&sigma),
            z1: to_num_bigint(&z1),
            z2: to_num_bigint(&z2),
            w1: to_num_bigint(&w1),
            w2: to_num_bigint(&w2),
            v: to_num_bigint(&v),
            salt: salt.to_owned(),
        }
    }

    pub fn verify(&self, setup: &DLogStatement, N0: &BigInt) -> bool {
        let N_tilde = setup.N.clone();
        let s = setup.g.clone();
        let t = setup.ni.clone();
        let sqrt_N0 = N0.sqrt();

        let sigma = from_num_bigint(&self.sigma);
        let z1 = from_num_bigint(&self.z1);
        let z2 = from_num_bigint(&self.z2);
        let w1 = from_num_bigint(&self.w1);
        let w2 = from_num_bigint(&self.w2);
        let v = from_num_bigint(&self.v);

        let bound_alpha_beta = &sqrt_N0 * &BigInt::from(2).pow(L + EPSILON);
        if z1 > bound_alpha_beta || z1 < -&bound_alpha_beta {
            return false;
        }
        if z2 > bound_alpha_beta || z2 < -&bound_alpha_beta {
            return false;
        }

        if N_tilde.bit_length() < 2046 {
            return false;
        }

        for value in vec![&self.P, &self.Q, &self.A, &self.B, &self.T] {
            // TODO: aren'they the same?
            if value.gcd(&N_tilde) != BigInt::one() || value % &N_tilde == BigInt::zero() {
                return false;
            }
        }

        let mut hasher = Sha512::new();
        for value in vec![N0, &self.P, &self.Q, &self.A, &self.B, &self.T, &sigma] {
            let as_vec = BigInt::to_bytes(&value);
            let vec_length = u16::try_from(as_vec.len()).expect("BigInt: bit length too big");
            hasher.update(vec_length.to_le_bytes());
            hasher.update(&as_vec);
        }
        if self.salt.len() > 0 {
            hasher.update(self.salt.clone());
        }
        let digest = hasher.finalize();
        let mut e = BigInt::from_bytes(&digest[0..32]);
        if (digest[63] & 0x01) != 0 {
            e = e.neg();
        }

        let R =
            (mod_any_pow(&s, N0, &N_tilde) * mod_any_pow(&t, &sigma, &N_tilde)).modulus(&N_tilde);

        if (mod_any_pow(&s, &z1, &N_tilde) * mod_any_pow(&t, &w1, &N_tilde)).modulus(&N_tilde)
            != (&self.A * mod_any_pow(&self.P, &e, &N_tilde)).modulus(&N_tilde)
        {
            return false;
        }

        if (mod_any_pow(&s, &z2, &N_tilde) * mod_any_pow(&t, &w2, &N_tilde)).modulus(&N_tilde)
            != (&self.B * mod_any_pow(&self.Q, &e, &N_tilde)).modulus(&N_tilde)
        {
            return false;
        }

        if (mod_any_pow(&self.Q, &z1, &N_tilde) * mod_any_pow(&t, &v, &N_tilde)).modulus(&N_tilde)
            != (&self.T * mod_any_pow(&R, &e, &N_tilde)).modulus(&N_tilde)
        {
            return false;
        }

        return true;
    }
}

fn mod_any_pow(base: &BigInt, exponent: &BigInt, modulus: &BigInt) -> BigInt {
    let res = BigInt::mod_pow(base, &exponent.abs(), modulus);
    if *exponent >= BigInt::zero() {
        return res;
    } else {
        return BigInt::mod_inv(&res, modulus).unwrap();
    }
}

fn to_num_bigint(input: &BigInt) -> BN {
    if BigInt::is_negative(input) {
        return BN::from_bytes_be(Sign::Minus, &input.to_bytes());
    } else {
        return BN::from_bytes_be(Sign::Plus, &input.to_bytes());
    }
}

fn from_num_bigint(input: &BN) -> BigInt {
    let (sign, bytes) = BN::to_bytes_be(input);
    if sign == Sign::Minus {
        return -BigInt::from_bytes(&bytes);
    } else {
        return BigInt::from_bytes(&bytes);
    }
}
