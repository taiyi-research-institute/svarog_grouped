use std::collections::HashMap;
pub type SparseArray<T> = HashMap<usize, T>;

mod aes;
pub use aes::*;
mod keygen;
pub use keygen::*;
mod sign;
pub use sign::*;
mod pubkey;
pub use pubkey::*;
mod hd;
pub use hd::*;

pub trait ToVecByKeyOrder<T> {
    fn values_sorted_by_key_asc(&self) -> Vec<T>;
    fn keys_asc(&self) -> Vec<usize>;
}

impl<T> ToVecByKeyOrder<T> for SparseArray<T>
where
    T: Clone,
{
    fn values_sorted_by_key_asc(&self) -> Vec<T> {
        // get all keys of a hashmap in ascending order
        // https://stackoverflow.com/questions/27582739/how-do-i-get-all-keys-of-a-hashmap-in-ascending-order
        let mut keys: Vec<usize> = self.keys().cloned().collect();
        keys.sort();
        let mut vals: Vec<T> = Vec::with_capacity(self.len());

        for key in keys {
            vals.push(self.get(&key).unwrap().clone())
        }
        vals
    }

    fn keys_asc(&self) -> Vec<usize> {
        let mut keys: Vec<usize> = self.keys().cloned().collect();
        keys.sort();
        keys
    }
}
