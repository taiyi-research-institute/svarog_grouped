use std::{fs::File, io::Write};

use svarog_mpc_sdk::mpc_member::*;
pub use svarog_mpc_sdk::mta::range_proofs::{
    ZkpPublicSetup, ZkpSetup, DEFAULT_GROUP_ORDER_BIT_LENGTH,
};

fn main() {
    let mut rgp_vec = Vec::new();
    for i in 0..50 {
        let mut range_proof_setup = ZkpSetup::random(DEFAULT_GROUP_ORDER_BIT_LENGTH);
        let mut range_proof_public_setup =
            ZkpPublicSetup::from_private_zkp_setup(&range_proof_setup).unwrap();
        let mut res = range_proof_public_setup.verify();
        while let Err(e) = res {
            println!("{:#?}", e);
            range_proof_setup = ZkpSetup::random(DEFAULT_GROUP_ORDER_BIT_LENGTH);
            range_proof_public_setup =
                ZkpPublicSetup::from_private_zkp_setup(&range_proof_setup).unwrap();
            res = range_proof_public_setup.verify();
        }
        rgp_vec.push(range_proof_public_setup);
        println!("Party {} RGP generated", i);
    }
    let compressed_json_bytes = rgp_vec.compress().unwrap();
    println!("Compressed JSON bytes: {:?}", compressed_json_bytes.len());
    let mut file = File::create("rgp_vec.dat").unwrap();
    file.write_all(&compressed_json_bytes).unwrap();
}
