use std::collections::HashMap;

use xuanmi_base_support::*;
pub type SparseVec<T> = HashMap<usize, T>;
pub type Grid<T> = HashMap<(usize, usize), T>;

pub trait ToVecByKeyOrder<T> {
    fn values_sorted_by_key_asc(&self) -> Vec<T>;
    fn keys_asc(&self) -> Vec<usize>;
}

impl<T> ToVecByKeyOrder<T> for SparseVec<T>
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

pub fn sparsevec_to_grid<T>(v: &SparseVec<Vec<T>>) -> Grid<T>
where
    T: Clone,
{
    let nrow = v.len();
    let ncol = if let Some(row_vec) = v.values().next() {
        row_vec.len()
    } else {
        0
    };
    let mut grid: HashMap<(usize, usize), T> = Grid::with_capacity(nrow * ncol);
    for (row, row_vec) in v.iter() {
        for (col, val) in row_vec.iter().enumerate() {
            grid.insert((*row, col), val.clone());
        }
    }
    grid
}
