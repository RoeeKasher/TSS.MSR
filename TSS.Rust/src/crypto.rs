use crate::tpm_types::{TPM_ALG_ID, TPMT_HA};

pub struct Crypto;

impl Crypto {
    pub fn digestSize(alg: TPM_ALG_ID) -> usize {
        match alg {
            TPM_ALG_ID::SHA1 => 20,
            TPM_ALG_ID::SHA256 => 32,
            TPM_ALG_ID::SHA384 => 48,
            TPM_ALG_ID::SHA512 => 64,
            _ => panic!("Unsupported algorithm"),
        }
    }
    
    // Hash a byte buffer using the specified algorithm
    pub fn Hash(alg: TPM_ALG_ID, data: &[u8]) -> Vec<u8> {
        // This is a placeholder implementation - in a real implementation this would
        // call the actual crypto library functions for the specified algorithm
        vec![0; Self::digestSize(alg)] // Return zeroed digest of the correct length
    }
    
    // Hash a portion of a byte buffer using the specified algorithm
    pub fn Hash(alg: TPM_ALG_ID, data: &[u8], start_pos: usize, length: usize) -> Vec<u8> {
        if start_pos + length > data.len() {
            panic!("Invalid buffer range");
        }
        Self::Hash(alg, &data[start_pos..(start_pos + length)])
    }
    
    // Hash a byte buffer using the hash algorithm specified in a TPMT_HA
    pub fn Hash(hash_algo_struct: TPMT_HA, data: &[u8]) -> Vec<u8> {
        Self::Hash(hash_algo_struct.hashAlg, data)
    }
}