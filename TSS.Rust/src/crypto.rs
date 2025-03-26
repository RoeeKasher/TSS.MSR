use crate::tpm_types::TPM_ALG_ID;

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
}