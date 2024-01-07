use std::collections::{HashMap, HashSet};

use crate::{assert_throw, exception::*};
use serde::{Deserialize, Serialize};
use curv::cryptographic_primitives::secret_sharing::Polynomial;
use curv::elliptic::curves::{Curve, Point, Scalar};

/// Shared secret produced by [VerifiableSS::share]
///
/// After you shared your secret, you need to distribute `shares` among other parties, and erase
/// secret from your memory (SharedSecret zeroizes on drop).
///
/// You can retrieve a [polynomial](Self::polynomial) that was used to derive secret shares. It is
/// only needed to combine with other proofs (e.g. [low degree exponent interpolation]).
///
/// [low degree exponent interpolation]: crate::cryptographic_primitives::proofs::low_degree_exponent_interpolation
#[derive(Clone, Debug)]
pub struct SecretShares<E: Curve> {
    pub shares: HashMap<u16, Scalar<E>>,
    pub polynomial: Polynomial<E>,
}

#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
pub struct ShamirSecretSharing {
    pub threshold: u16,   //t
    pub share_count: u16, //n
}

/// Feldman VSS, based on  Paul Feldman. 1987. A practical scheme for non-interactive verifiable secret sharing.
/// In Foundations of Computer Science, 1987., 28th Annual Symposium on.IEEE, 427–43
///
/// implementation details: The code is using FE and GE. Each party is given an index from 1,..,n and a secret share of type FE.
/// The index of the party is also the point on the polynomial where we treat this number as u32 but converting it to FE internally.
#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
#[serde(bound = "")]
pub struct VerifiableSS<E: Curve> {
    pub parameters: ShamirSecretSharing,
    pub commitments: Vec<Point<E>>,
}

impl<E: Curve> VerifiableSS<E> {
    // generate VerifiableSS from a secret
    pub fn share(
        th: u16,
        secret: &Scalar<E>,
        keygen_members: &HashSet<u16>,
    ) -> Outcome<(VerifiableSS<E>, SecretShares<E>)> {
        assert_throw!(usize::from(th) < keygen_members.len());

        let polynomial = Polynomial::<E>::sample_exact_with_fixed_const_term(th, secret.clone());
        let mut shares: HashMap<u16, Scalar<E>> = HashMap::new();
        for member_id in keygen_members.iter() {
            shares.insert(*member_id, polynomial.evaluate_bigint(*member_id));
        }

        let mut commitments: Vec<Point<E>> = Vec::new();
        let g = Point::<E>::generator();
        for coef in polynomial.coefficients().iter() {
            commitments.push(g * coef);
        }
        let vss = VerifiableSS {
            parameters: ShamirSecretSharing {
                threshold: th,
                share_count: keygen_members.len() as u16,
            },
            commitments,
        };
        let shares = SecretShares { shares, polynomial };
        let ret = (vss, shares);
        Ok(ret)
    }

    // Performs a Lagrange interpolation in field Zp at the origin
    // for a polynomial defined by `points` and `values`.
    // `points` and `values` are expected to be two arrays of the same size, containing
    // respectively the evaluation points (x) and the value of the polynomial at those point (p(x)).
    // The result is the value of the polynomial at x=0. It is also its zero-degree coefficient.
    // This is obviously less general than `newton_interpolation_general`,
    // as we only get a single value, but it is much faster.
    pub fn reconstruct(
        &self,
        shares_of_all_signers: &HashMap<u16, Scalar<E>>,
    ) -> Outcome<Scalar<E>> {
        assert_throw!(shares_of_all_signers.len() > self.parameters.threshold as usize);

        let mut lagrange_coef: Vec<Scalar<E>> = Vec::new();
        for (member_id, share) in shares_of_all_signers.iter() {
            let xi: Scalar<E> = Scalar::from(*member_id);
            let yi: &Scalar<E> = share;
            let mut num: Scalar<E> = Scalar::from(1);
            for other_member_id in shares_of_all_signers.keys() {
                if other_member_id != member_id {
                    let xj: Scalar<E> = Scalar::from(*other_member_id);
                    num = num * xj;
                }
            }
            let mut denum: Scalar<E> = Scalar::from(1);
            for other_id in shares_of_all_signers.keys() {
                if other_id == member_id {
                    continue;
                }
                let xj_sub_xi: Scalar<E> = Scalar::from(*other_id) - &xi;
                denum = denum * xj_sub_xi;
            }
            denum = denum
                .invert()
                .ifnone("AlgorithmException (VSS)", "denum is zero")?;
            lagrange_coef.push(num * denum * yi);
        }
        assert_throw!(lagrange_coef.len() > 1);

        let mut res = lagrange_coef[0].clone();
        for idx in 1..lagrange_coef.len() {
            res = res + &lagrange_coef[idx];
        }
        Ok(res)
    }

    pub fn validate_share(&self, secret_share: &Scalar<E>, member_id: u16) -> Outcome<()> {
        let g = Point::generator();
        let ss_point = g * secret_share;
        self.validate_share_public(&ss_point, member_id).catch_()?;
        Ok(())
    }

    pub fn validate_share_public(&self, ss_point: &Point<E>, index: u16) -> Outcome<()> {
        let comm_to_point = self.get_point_commitment(index).catch_()?;
        assert_throw!(*ss_point == comm_to_point, "VerifyShareFailed");
        Ok(())
    }

    pub fn get_point_commitment(&self, member_id: u16) -> Outcome<Point<E>> {
        let member_fe = Scalar::from(member_id);
        let mut it = self.commitments.iter().rev();
        let mut comm = it.next().ifnone_()?.clone();
        while let Some(x) = it.next() {
            comm = x + comm * &member_fe;
        }
        Ok(comm)
    }

    // compute \lambda_{index,S}, a lagrangian coefficient that change the (t,n) scheme to (|S|,|S|)
    // used in http://stevengoldfeder.com/papers/GG18.pdf
    pub fn map_share_to_new_params(
        member_id: u16,
        shard_providers: &HashSet<u16>,
    ) -> Outcome<Scalar<E>> {
        assert_throw!(shard_providers.contains(&member_id));
        let x: Scalar<E> = Scalar::zero();
        let x_j: Scalar<E> = Scalar::from(member_id);

        let mut num: Scalar<E> = Scalar::from(1);
        for other_id in shard_providers.iter() {
            if *other_id == member_id {
                continue;
            }
            let x_m: Scalar<E> = Scalar::from(*other_id);
            num = num * (&x - &x_m);
        }

        let mut denum: Scalar<E> = Scalar::from(1);
        for other_id in shard_providers.iter() {
            if *other_id == member_id {
                continue;
            }
            let x_m: Scalar<E> = Scalar::from(*other_id);
            denum = denum * (&x_j - &x_m);
        }
        denum = denum
            .invert()
            .ifnone("AlgorithmException (VSS)", "denum is zero")?;
        Ok(num * denum)
    }
}