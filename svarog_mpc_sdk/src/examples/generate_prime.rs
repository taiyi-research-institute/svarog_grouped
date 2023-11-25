use std::{fs::File, io::Write};

use svarog_mpc_sdk::gg18::Keys;
use svarog_mpc_sdk::mpc_member::*;

fn main() {
    let mut party_keys_vec = Vec::new();
    for i in 0..50 {
        let party_keys = Keys::create_with_safe_prime(i as u16); // instead of kzen::Keys::create(my_id)
        party_keys_vec.push(party_keys);
        println!("Party {} keys generated", i);
    }
    let compressed_json_bytes = party_keys_vec.compress().unwrap();
    println!("Compressed JSON bytes: {:?}", compressed_json_bytes.len());
    let mut file = File::create("party_keys_vec.dat").unwrap();
    file.write_all(&compressed_json_bytes).unwrap();
}
