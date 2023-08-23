pub type Vss = VerifiableSS<Secp256k1>;

#[derive(Clone, Serialize, Deserialize)]
pub struct KeyStore {
    pub root_pubkey: Point<Secp256k1>,
    pub chain_code: [u8; 32],
    pub party_keys: GG18Keys,
    pub shared_keys: GG18SharedKeys,
    pub vss_schemes: SparseArray<Vss>,
    pub paillier_keys: SparseArray<EncryptionKey>,

    pub config: SessionConfig,
}