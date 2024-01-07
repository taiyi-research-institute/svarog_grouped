//! This file is a modified version of ING bank's group element sampling implementation:
//! https://github.com/ing-bank/threshold-signatures/blob/master/src/algorithms/mod.rs
//! to support curv-kzen from v0.2.8 to v0.9.0

//! Zero knowledge range proofs, safe prime generator and SHA512-256 wrapper
//!

use crate::{assert_throw, exception::*, throw};
use curv::{
    arithmetic::{traits::Samplable, Integer, Modulo, One, Zero},
    BigInt,
};

/// Finds a generator of  a cyclic group of order n
/// using known factorization of n.
///
/// See "Handbook of applied cryptography", algorithm 4.80
pub fn sample_generator_from_cyclic_group(
    modulo: &BigInt,
    order: &BigInt,
    order_factorization: &[&BigInt],
) -> BigInt {
    let One = BigInt::one();
    'outer: loop {
        let alpha = BigInt::sample_below(modulo);
        for &x in order_factorization {
            let alpha_modpow = BigInt::mod_pow(&alpha, &(order / x), modulo);
            if alpha_modpow == One {
                continue 'outer;
            }
        }
        return alpha;
    }
}

/// Solves the system of simultaneous congruences (CRT) with Gauss' algorithm
///
/// See "Handbook of applied cryptography", algorithm 2.121
pub fn crt_solver(remainders: &[&BigInt], moduli: &[&BigInt]) -> Outcome<BigInt> {
    let mut n = BigInt::one();
    for &m in moduli {
        n = n * m;
    }
    let mut ret = BigInt::zero();
    for (&ai, &ni) in remainders.iter().zip(moduli) {
        let Ni: BigInt = &n / ni;
        let Mi: BigInt = BigInt::mod_inv(&Ni, &ni).ifnone_()?;
        ret += (ai * Ni * Mi) % &n;
    }
    ret = ret % n;
    Ok(ret)
}

/// Samples a generator from RSA group modulo product of two safe primes
///
/// Samples elements from two cyclic subgroups modulo prime p = (P-1)/2.
/// Finds the generator using CRT
///
pub fn sample_generator_of_rsa_group(safe_p: &BigInt, safe_q: &BigInt) -> Outcome<BigInt> {
    let One = &BigInt::one();
    let Two = &BigInt::from(2);

    let p_prim = (safe_p - One) / Two;
    let q_prim = (safe_q - One) / Two;

    // find generators in prime order subgroups of groups modulo safe_p and safe_q
    let g_p = sample_generator_of_cyclic_subgroup(safe_p, &p_prim).catch_()?;
    let g_q = sample_generator_of_cyclic_subgroup(safe_q, &q_prim).catch_()?;
    let ret = crt_solver(&[&g_p, &g_q], &[safe_p, safe_q]).catch_()?;
    Ok(ret)
}

/// Sample a generator from cyclic subgroup of the group modulo safe prime
///
/// Samples an element from cyclic subgroup of $` Z^{*}_p `$ of order $` p' `$
/// where $` p,p' `$ are prime and $` p' | (p-1) `$. As the group is cyclic, the element is the generator.
///  
/// See "Introduction to modern cryptography", 2nd ed , Algorithm 8.65
pub fn sample_generator_of_cyclic_subgroup(p: &BigInt, q: &BigInt) -> Outcome<BigInt> {
    // q | (p - 1), G is order-q subgroup of Zp^*
    const MAX_ITERATIONS_IN_REJECTION_SAMPLING: usize = 256;

    let p_minus_one = p - &BigInt::one();
    assert_throw!(
        p_minus_one.is_multiple_of(&q),
        "incorrect input for sampling a generator of the subgroup"
    );
    let exp = p_minus_one / q;
    for _ in 0..MAX_ITERATIONS_IN_REJECTION_SAMPLING {
        let h = BigInt::sample_below(p);
        let cond = h != BigInt::one() && BigInt::mod_pow(&h, &exp, p) != BigInt::one();
        if cond {
            return Ok(BigInt::mod_pow(&h, &exp, p));
        }
    }
    throw!(
        "",
        &format!(
            "rejection sampling exceeded {} iterations in sample_generator_from_cyclic_subgroup()",
            MAX_ITERATIONS_IN_REJECTION_SAMPLING
        )
    );
}
