mod keystore;
pub use keystore::*;
mod signature;
use curv::{arithmetic::Converter, BigInt};
pub use signature::*;
use xuanmi_base_support::*;

const BIGINT_HEX: &'static str = "bigint_hex:";
const BYTES_HEX: &'static str = "bytes_hex:";

pub fn bytes_from_hex(hex: &str) -> Outcome<Vec<u8>> {
    const ERR_BYTES: &'static str = "Hex string of bytes should begin with \"bytes_hex\"";
    if hex.len() < BYTES_HEX.len() {
        throw!(name = "IncorrectPrefixError", ctx = ERR_BYTES);
    }
    if &hex[..BYTES_HEX.len()] != BYTES_HEX {
        throw!(name = "IncorrectPrefixError", ctx = ERR_BYTES);
    }
    hex::decode(&hex[BYTES_HEX.len()..]).catch("HexToBytesException", "")
}

pub fn bytes_to_hex(bytes: &[u8]) -> String {
    let mut hex_str = String::from(BYTES_HEX);
    hex_str.push_str(hex::encode(bytes).as_str());
    hex_str
}

fn bigint_from_hex(hex: &str) -> Outcome<BigInt> {
    const ERR_BIGINT: &'static str = "Hex string of bytes should begin with \"bytes_hex\"";
    if hex.len() < BIGINT_HEX.len() {
        throw!(name = "IncorrectPrefixError", ctx = ERR_BIGINT);
    }
    if &hex[..BIGINT_HEX.len()] != BIGINT_HEX {
        throw!(name = "IncorrectPrefixError", ctx = ERR_BIGINT);
    }
    BigInt::from_hex(&hex[BIGINT_HEX.len()..]).catch("HexToBigIntException", "")
}

fn bigint_to_hex(bigint: &BigInt) -> String {
    let mut hex_str = String::from(BIGINT_HEX);
    hex_str.push_str(bigint.to_hex().as_str());
    hex_str
}
