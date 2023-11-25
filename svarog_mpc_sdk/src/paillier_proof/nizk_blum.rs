#![allow(non_snake_case)]
use curv::{
    arithmetic::{BasicOps, BitManipulation, Converter, Integer, Modulo, One, Samplable, Zero},
    BigInt,
};
use paillier::DecryptionKey;
use serde::{Deserialize, Serialize};
use xuanmi_base_support::*;

use crate::mta::*;

const LEN_N: u16 = 2048;
const M: u16 = 128; // 80;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PaillierBlumModProof {
    pub w: BigInt,
    pub assoc_vec: Vec<AssocValues>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AssocValues {
    pub x_i: BigInt,
    pub a_i: i32,
    pub b_i: i32,
    pub z_i: BigInt,
}

impl PaillierBlumModProof {
    pub fn generate(N: &BigInt, dk: &DecryptionKey, binding: &BigInt) -> Outcome<Self> {
        let setup_check = *N == &dk.p * &dk.q
            && dk.p.modulus(&BigInt::from(4)) == BigInt::from(3)
            && dk.q.modulus(&BigInt::from(4)) == BigInt::from(3);
        assert_throw!(setup_check, "PaillierProofError.InvalidSetup");

        let mut w = BigInt::sample_below(N);
        while jacobi(&w, N) != Some(-1) {
            w = BigInt::sample_below(N);
        }
        let mut assoc_vec: Vec<AssocValues> = Vec::with_capacity(M as usize);
        for i in 1..=M {
            assoc_vec.push(AssocValues::generate(N, dk, &w, i, binding)?);
        }
        Ok(PaillierBlumModProof { w, assoc_vec })
    }

    pub fn verify(&self, N: &BigInt, binding: &BigInt) -> bool {
        if *N <= BigInt::one() || N.bit_length() < 2046 {
            return false;
        }
        if N.is_even() {
            return false;
        }
        if is_prime(N) {
            return false;
        }
        if self.w <= BigInt::zero() || self.w >= *N {
            return false;
        }
        if self.assoc_vec.len() != M as usize {
            return false;
        }
        if jacobi(&self.w, N) != Some(-1) {
            return false;
        }
        for i in 1..=M {
            let assoc = &self.assoc_vec[i as usize - 1];
            if assoc.x_i <= BigInt::zero()
                || assoc.x_i >= *N
                || assoc.z_i <= BigInt::one()
                || assoc.z_i >= *N
            {
                return false;
            }
            if assoc.z_i.gcd(N) != BigInt::one() {
                return false;
            }

            let y_i = gen_y(N, &self.w, i, binding);
            if BigInt::mod_pow(&assoc.z_i, N, N) != y_i.modulus(N) {
                return false;
            }
            if assoc.a_i < 0 || assoc.a_i > 1 || assoc.b_i < 0 || assoc.b_i > 1 {
                return false;
            }
            if assoc.x_i.pow(4).modulus(N)
                != BigInt::from(-1)
                    .pow(assoc.a_i as u32)
                    .mul(&self.w.pow(assoc.b_i as u32).mul(&y_i))
                    .modulus(N)
            {
                return false;
            }
        }
        true
    }
}

impl AssocValues {
    pub fn generate(
        N: &BigInt,
        dk: &DecryptionKey,
        w: &BigInt,
        i: u16,
        binding: &BigInt,
    ) -> Outcome<Self> {
        let phi = (&dk.p - 1) * (&dk.q - 1);
        let y_i = gen_y(N, &w, i, binding);
        let z_i = BigInt::mod_pow(&y_i, &BigInt::mod_inv(N, &phi).unwrap(), N);
        let a_i_b_i_vec: [(i32, i32); 4] = [(0, 0), (0, 1), (1, 0), (1, 1)];
        let y_i_tilde_vec: [BigInt; 4] = [y_i.clone(), w * &y_i, -&y_i, -w * &y_i];

        for i in 0..y_i_tilde_vec.len() {
            if is_quad_residue(&y_i_tilde_vec[i], dk) {
                let x_i = fourth_root_mod(&y_i_tilde_vec[i], N, dk)?;
                let (a_i, b_i) = a_i_b_i_vec[i];
                return Ok(AssocValues { x_i, a_i, b_i, z_i });
            }
        }
        throw!("PaillierProofError.FindFourthRootFailed", "");
    }
}

pub fn gen_y(N: &BigInt, w: &BigInt, i: u16, binding: &BigInt) -> BigInt {
    use sha3::{
        digest::{ExtendableOutput, Update, XofReader},
        Shake256,
    };

    let mut counter = 0u32;
    const SALT: &str = "paillierblummodulusproof";
    const DSE: &str = "|";
    loop {
        let mut hasher = Shake256::default();
        hasher.update(&DSE.as_bytes());
        for value in [
            N,
            w,
            &BigInt::from(i),
            binding,
            &BigInt::from_bytes(SALT.as_bytes()),
            &BigInt::from(counter),
        ] {
            let as_vec = BigInt::to_bytes(&value);
            let vec_length = u16::try_from(as_vec.len()).expect("BigInt: bit length too big");
            hasher.update(&vec_length.to_le_bytes());
            hasher.update(&as_vec);
        }
        let mut reader = hasher.finalize_xof();
        let mut res = [0u8; LEN_N as usize / 8];
        reader.read(&mut res);
        let candidate = BigInt::from_bytes(&res).modulus(N);
        if candidate.gcd(N) == BigInt::one() {
            return candidate;
        } else {
            counter += 1;
        }
    }
}

pub fn fourth_root_mod(x: &BigInt, N: &BigInt, dk: &DecryptionKey) -> Outcome<BigInt> {
    if *N == &dk.p * &dk.q
        && dk.p.modulus(&BigInt::from(4)) == BigInt::from(3)
        && dk.q.modulus(&BigInt::from(4)) == BigInt::from(3)
    {
        let phi = (&dk.p - 1) * (&dk.q - 1);
        return Ok(BigInt::mod_pow(x, &((phi + 4) / 8).pow(2u32), N));
    } else {
        throw!("PaillierProofError.InvalidInputFourthRoot", "");
    }
}

pub fn is_quad_residue(x: &BigInt, dk: &DecryptionKey) -> bool {
    // note that mod p and mod q, not mod N
    return BigInt::mod_pow(&x, &((&dk.p - 1) / 2), &dk.p) == BigInt::one()
        && BigInt::mod_pow(&x, &((&dk.q - 1) / 2), &dk.q) == BigInt::one();
}

// copied from https://docs.rs/crate/quadratic/0.3.1/source/src/lib.rs
// changed to support curv::BigInt
pub fn jacobi(a: &BigInt, n: &BigInt) -> Option<i8> {
    let zero = BigInt::zero();
    // jacobi symbol is only defined for odd positive moduli
    if n.mod_floor(&BigInt::from(2)) == zero || n <= &BigInt::zero() {
        return None;
    }

    // Raise a mod n, then start the unsigned algorithm
    let mut acc = 1;
    let mut num = a.mod_floor(&n);
    let mut den = n.clone();
    loop {
        // reduce numerator
        num = num.mod_floor(&den);
        if num == zero {
            return Some(0);
        }

        // extract factors of two from numerator
        while num.mod_floor(&BigInt::from(2)) == zero {
            acc *= two_over(&den);
            num = num.div_floor(&BigInt::from(2));
        }
        // if numerator is 1 => this sub-symbol is 1
        if num == BigInt::one() {
            return Some(acc);
        }
        // shared factors => one sub-symbol is zero
        if num.gcd(&den) > BigInt::one() {
            return Some(0);
        }
        // num and den are now odd co-prime, use reciprocity law:
        acc *= reciprocity(&num, &den);
        let tmp = num;
        num = den.clone();
        den = tmp;
    }
}

// copied from https://docs.rs/crate/quadratic/0.3.1/source/src/lib.rs
// changed to support curv::BigInt
fn two_over(n: &BigInt) -> i8 {
    let n_mod_8 = n.mod_floor(&BigInt::from(8));
    if n_mod_8 == BigInt::one() || n_mod_8 == BigInt::from(7) {
        1
    } else {
        -1
    }
}

// copied from https://docs.rs/crate/quadratic/0.3.1/source/src/lib.rs
// changed to support curv::BigInt
fn reciprocity(num: &BigInt, den: &BigInt) -> i8 {
    let three = BigInt::from(3);
    let four = BigInt::from(4);
    if num.mod_floor(&four) == three && den.mod_floor(&four) == three {
        -1
    } else {
        1
    }
}
