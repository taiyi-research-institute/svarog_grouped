// replace (bitcoin::util::bip32, secp256k1) by (bip32, k256 v0.11.0)
use crate::{assert_throw, exception::*, throw};
use bip32::{
    ChainCode, ChildNumber, DerivationPath, ExtendedKey, ExtendedKeyAttrs, Prefix, PrivateKey,
    PublicKey, XPrv, XPub, KEY_SIZE,
};
use curv::elliptic::curves::{secp256_k1::Secp256k1, Point, Scalar};
use hmac::{Hmac, Mac, NewMac};
use sha2::Sha512;
use std::{convert::TryInto, str::FromStr};

// struct HmacSha512(hmac::Hmac<sha2::Sha512>);
// impl Mac for HmacSha512 {}
type HmacSha512 = Hmac<Sha512>;
type HdKey = (Scalar<Secp256k1>, Point<Secp256k1>);

// input: path_str (&str), public_key (Point<Secp256k1>)
// output: tweak_sk (Scalar<Secp256k1>), new_public_key (Point<Secp256k1>)
pub fn algo_get_hd_key(
    derive: &str,
    par_pk: &Point<Secp256k1>,
    chain_code: &ChainCode,
) -> Outcome<HdKey> {
    let HDE = "HdKeyException";
    let path = DerivationPath::from_str(derive).catch(
        HDE,
        &format!("String \"{}\" is not a valid derivation path", derive),
    )?;
    let encoded_par_pk = par_pk.to_bytes(true);
    let par_pk_bytes: &[u8] = encoded_par_pk.as_ref();
    assert_throw!(par_pk_bytes.len() == 33);

    let mut ex_pk = ExtendedKey {
        prefix: Prefix::XPUB,
        attrs: ExtendedKeyAttrs {
            parent_fingerprint: [0u8; 4],
            child_number: ChildNumber(0u32),
            chain_code: *chain_code,
            depth: 0u8,
        },
        key_bytes: par_pk_bytes.try_into().unwrap(),
    };
    let mut pk = XPub::try_from(ex_pk.clone()).catch(
        HDE,
        &format!("Cannot create XPub from ex_pk_b58={}", &ex_pk.to_string()),
    )?;
    let ex_sk = ExtendedKey {
        prefix: Prefix::XPRV,
        attrs: ExtendedKeyAttrs {
            parent_fingerprint: [0u8; 4],
            child_number: ChildNumber(0u32),
            chain_code: *chain_code,
            depth: 0u8,
        },
        key_bytes: [
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 1,
        ],
    };
    let scalar_one = XPrv::try_from(ex_sk.clone()).catch(
        HDE,
        &format!("Cannot create XPrv from ex_sk_b58={}", &ex_sk.to_string()),
    )?;
    let mut total_tweak = scalar_one.private_key().clone();
    for ccnum in path.as_ref() {
        let depth: u8 = pk.attrs().depth.checked_add(1).ifnone(HDE, "Depth")?;
        let mut hmac: HmacSha512 =
            HmacSha512::new_from_slice(&pk.attrs().chain_code).catch(HDE, "Crypto")?;
        if ccnum.is_hardened() {
            throw!(
                HDE,
                "Cannot derive child public keys for hardened `ChildNumber`s"
            );
        } else {
            hmac.update(&pk.public_key().to_bytes());
        }
        hmac.update(&ccnum.to_bytes());
        let result = hmac.finalize().into_bytes();
        let (tweak, chain_code) = result.split_at(KEY_SIZE);
        if tweak.len() != 32 {
            throw!(
                HDE,
                &format!(
                    "Invalid tweak length {} (expected length {})",
                    tweak.len(),
                    KEY_SIZE
                )
            );
        }
        if chain_code.len() != 32 {
            throw!(
                HDE,
                &format!(
                    "Invalid chain code length {} (expected length {})",
                    chain_code.len(),
                    KEY_SIZE
                )
            );
        }
        let public_key = pk
            .public_key()
            .derive_child(tweak.try_into().unwrap())
            .catch(HDE, "")?;
        total_tweak = total_tweak
            .derive_child(tweak.try_into().unwrap())
            .catch(HDE, "")?;

        ex_pk = ExtendedKey {
            prefix: Prefix::XPUB,
            attrs: ExtendedKeyAttrs {
                parent_fingerprint: pk.public_key().fingerprint(),
                child_number: *ccnum,
                chain_code: chain_code.try_into().unwrap(),
                depth,
            },
            key_bytes: {
                let ga = public_key.to_bytes();
                if ga.len() != 33 {
                    throw!(
                        "HDE",
                        &format!(
                            "Invalid public key length. Expected {}, provided {}",
                            33,
                            ga.len()
                        )
                    );
                }
                ga
            },
        };

        pk = XPub::try_from(ex_pk).catch(HDE, "")?;
    }

    let tweak_sk: Scalar<Secp256k1> = Scalar::from_bytes(&total_tweak.to_bytes()).catch(
        HDE,
        "Failed to deserialize total_tweak to Scalar<Secp256k1>",
    )? - Scalar::from(1u32);
    let child_pk: Point<Secp256k1> =
        Point::from_bytes(&pk.public_key().to_bytes()).catch(HDE, "Failed to deserialize ")?;

    Ok((tweak_sk, child_pk))
}

#[cfg(test)]
mod tests {
    use std::ops::Deref;

    use crate::biz_algo::algo_get_hd_key;
    use crate::{exception::*, throw};
    use curv::elliptic::curves::{secp256_k1::Secp256k1, Point};
    const TE: &str = "TestException";

    #[test]
    fn test_get_hd_key() -> Outcome<()> {
        let derive = "m/0/1/2";
        let par_pk: Point<Secp256k1> = Point::from_bytes(
            &hex::decode("027897f2e4080bd0a4d658fa07838b0acaaaae17cc4d843d33f90565f5b248ab52")
                .catch(TE, "")?,
        )
        .catch(TE, "")?;
        let chain_code: [u8; 32] =
            (hex::decode("84bdc15254818c9b23b0703f95a9b96a514dae60d2798bc4f2cc8e496f59cae0")
                .catch(TE, "")?)
            .try_into()
            .unwrap();

        let (tweak_sk, child_pk) = algo_get_hd_key(derive, &par_pk, &chain_code)
            .catch("TestException", "algo_get_hd_key cannot execute to the end")?;
        let tweak_sk_hex = hex::encode(tweak_sk.to_bytes().deref());
        let child_pk_hex = hex::encode(child_pk.to_bytes(true).deref());
        let gt_tweak_sk_hex = "98e36de4c6e8b3b20efddae1d3937b6e7c3dd900fee5098cacb2303f7310166d";
        let gt_child_pk_hex = "0323a37212653d95036fcc055d3d257b04971dca6fba4cb219cff57fc08e2891ad";
        if tweak_sk_hex != gt_tweak_sk_hex {
            throw!("TestException", "algo_get_hd_key returns wrong tweak_sk");
        }
        if child_pk_hex != gt_child_pk_hex {
            throw!("TestException", "algo_get_hd_key returns wrong child_pk");
        }
        Ok(())
    }
}
