use crate::{assert_throw, exception::*, throw};
use core::default::Default;
use curv::{
    arithmetic::{BasicOps, BitManipulation, Converter, Integer, Modulo, One, Samplable, Zero},
    BigInt,
};
use paillier::DecryptionKey;
use serde::{Deserialize, Serialize};

const LEN_N: u16 = 2048;
const LEN_M: u16 = 128; // 80;

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
        let paillier_proof_valid_setup = {
            let mut cond = *N == &dk.p * &dk.q;
            cond &= dk.p.modulus(&BigInt::from(4)) == BigInt::from(3);
            cond &= dk.q.modulus(&BigInt::from(4)) == BigInt::from(3);
            cond
        };
        assert_throw!(paillier_proof_valid_setup);

        let mut w = BigInt::sample_below(N);
        while jacobi(&w, N) != Some(-1) {
            w = BigInt::sample_below(N);
        }
        let mut assoc_vec: Vec<AssocValues> = Vec::with_capacity(LEN_M as usize);
        for i in 1..=LEN_M {
            assoc_vec.push(AssocValues::generate(N, dk, &w, i, binding).catch_()?);
        }
        Ok(PaillierBlumModProof { w, assoc_vec })
    }

    pub fn verify(&self, N: &BigInt, binding: &BigInt) -> Outcome<()> {
        assert_throw!(N > &BigInt::one());
        assert_throw!(N.bit_length() >= 2046);
        assert_throw!(N.is_odd());

        use super::primes::is_prime;
        assert_throw!(!is_prime(N));

        assert_throw!(self.w > BigInt::zero());
        assert_throw!(self.w < *N);
        assert_throw!(self.assoc_vec.len() == LEN_M as usize);
        assert_throw!(jacobi(&self.w, N) == Some(-1));

        for i in 1..=LEN_M {
            let assoc = self.assoc_vec.get(i as usize - 1).ifnone_()?;
            assert_throw!(assoc.x_i > BigInt::zero());
            assert_throw!(assoc.x_i < *N);
            assert_throw!(assoc.z_i > BigInt::one());
            assert_throw!(assoc.z_i < *N);
            assert_throw!(assoc.z_i.gcd(N) == BigInt::one());
            let y_i = gen_y(N, &self.w, i, binding).catch_()?;
            assert_throw!(y_i.modulus(N) == BigInt::mod_pow(&assoc.z_i, N, N));
            assert_throw!(assoc.a_i == 0 || assoc.a_i == 1);
            assert_throw!(assoc.b_i == 0 || assoc.b_i == 1);
            assert_throw!(
                assoc.x_i.pow(4).modulus(N)
                    == BigInt::from(-1)
                        .pow(assoc.a_i as u32)
                        .mul(&self.w.pow(assoc.b_i as u32).mul(&y_i))
                        .modulus(N)
            );
        }

        Ok(())
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
        let y_i = gen_y(N, &w, i, binding).catch_()?;
        let z_i = BigInt::mod_pow(&y_i, &BigInt::mod_inv(N, &phi).unwrap(), N);
        let a_i_b_i_vec: [(i32, i32); 4] = [(0, 0), (0, 1), (1, 0), (1, 1)];
        let y_i_tilde_vec: [BigInt; 4] = [y_i.clone(), w * &y_i, -&y_i, -w * &y_i];

        for (i, y_i_tilde) in y_i_tilde_vec.iter().enumerate() {
            if is_quad_residue(y_i_tilde, dk) {
                let x_i = fourth_root_mod(y_i_tilde, N, dk).catch_()?;
                let (a_i, b_i) = a_i_b_i_vec[i];
                return Ok(AssocValues { x_i, a_i, b_i, z_i });
            }
        }
        throw!("", "Paillier proof error (failed to find 4th root)");
    }
}

pub fn gen_y(N: &BigInt, w: &BigInt, i: u16, binding: &BigInt) -> Outcome<BigInt> {
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
        let values = [
            N,
            w,
            &BigInt::from(i),
            binding,
            &BigInt::from_bytes(SALT.as_bytes()),
            &BigInt::from(counter),
        ];
        for value in values {
            let as_vec = BigInt::to_bytes(&value);
            let vec_length = u16::try_from(as_vec.len()).catch_()?;
            hasher.update(&vec_length.to_le_bytes());
            hasher.update(&as_vec);
        }
        let mut reader = hasher.finalize_xof();
        let mut res = [0u8; LEN_N as usize / 8];
        reader.read(&mut res);
        let candidate = BigInt::from_bytes(&res).modulus(N);
        if candidate.gcd(N) == BigInt::one() {
            return Ok(candidate);
        } else {
            counter += 1;
        }
    }
}

pub fn fourth_root_mod(x: &BigInt, N: &BigInt, dk: &DecryptionKey) -> Outcome<BigInt> {
    assert_throw!(*N == &dk.p * &dk.q);
    const ERR: &str = "Paillier proof error (input is not 4th root)";
    assert_throw!(dk.p.modulus(&BigInt::from(4)) == BigInt::from(3), ERR);
    assert_throw!(dk.q.modulus(&BigInt::from(4)) == BigInt::from(3), ERR);
    let phi = (&dk.p - 1) * (&dk.q - 1);
    let ret = BigInt::mod_pow(x, &((phi + 4) / 8).pow(2u32), N);
    Ok(ret)
}

pub fn is_quad_residue(x: &BigInt, dk: &DecryptionKey) -> bool {
    // note that mod p and mod q, not mod N
    return BigInt::mod_pow(&x, &((&dk.p - 1) / 2), &dk.p) == BigInt::one()
        && BigInt::mod_pow(&x, &((&dk.q - 1) / 2), &dk.q) == BigInt::one();
}

/// copied from https://docs.rs/crate/quadratic/0.3.1/source/src/lib.rs
/// changed to support curv::BigInt
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
