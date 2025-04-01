use crate::{error::TpmError, tpm_types::*};
use hmac::{Hmac, Mac};
use rsa::{pkcs1v15::{SigningKey, VerifyingKey}, BigUint, Pkcs1v15Sign, RsaPublicKey};
use sha1::Sha1;
use sha2::{Digest as Sha2Digest, Sha256, Sha384, Sha512};
use sm3::Sm3;

pub struct Crypto;

impl Crypto {
    // The function is called from an auto-generated file that expects this specific (non snake_cased) name
    #[allow(non_snake_case)]
    pub fn digestSize(alg: TPM_ALG_ID) -> usize {
        match alg {
            TPM_ALG_ID::SHA1 => 20,
            TPM_ALG_ID::SHA256 => 32,
            TPM_ALG_ID::SHA384 => 48,
            TPM_ALG_ID::SHA512 => 64,
            TPM_ALG_ID::SM3_256 => 32,
            _ => 0,
        }
    }

    // Hash a byte buffer using the specified algorithm
    pub fn hash(alg: TPM_ALG_ID, data: &[u8]) -> Result<Vec<u8>, TpmError> {
        // If the data is empty, return an empty digest of correct size
        if data.is_empty() {
            return Ok(vec![0; Self::digestSize(alg)]);
        }

        let digest = match alg {
            TPM_ALG_ID::SHA1 => {
                let mut hasher = Sha1::new();
                hasher.update(data);
                hasher.finalize().to_vec()
            }
            TPM_ALG_ID::SHA256 => {
                let mut hasher = Sha256::new();
                hasher.update(data);
                hasher.finalize().to_vec()
            }
            TPM_ALG_ID::SHA384 => {
                let mut hasher = Sha384::new();
                hasher.update(data);
                hasher.finalize().to_vec()
            }
            TPM_ALG_ID::SHA512 => {
                let mut hasher = Sha512::new();
                hasher.update(data);
                hasher.finalize().to_vec()
            }
            TPM_ALG_ID::SM3_256 => {
                let mut hasher = Sm3::new();
                hasher.update(data);
                hasher.finalize().to_vec()
            }
            _ => {
                return Err(TpmError::NotSupported(format!(
                    "Unsupported hash algorithm: {:?}",
                    alg
                )))
            }
        };

        let expected_size = Self::digestSize(alg);
        if (digest.len() != expected_size) {
            return Err(TpmError::InvalidArraySize(format!(
                "Hash output length mismatch: expected {}, got {}",
                expected_size,
                digest.len()
            )));
        }

        Ok(digest)
    }

    // HMAC implementation equivalent to the C++ version
    pub fn hmac(hash_alg: TPM_ALG_ID, key: &[u8], to_hash: &[u8]) -> Result<Vec<u8>, TpmError> {
        // Choose the appropriate HMAC algorithm based on the hash algorithm
        match hash_alg {
            TPM_ALG_ID::SHA1 => {
                let mut mac = Hmac::<Sha1>::new_from_slice(key).map_err(|_| {
                    TpmError::InvalidArraySize("HMAC can take key of any size".to_string())
                })?;
                mac.update(to_hash);
                Ok(mac.finalize().into_bytes().to_vec())
            }
            TPM_ALG_ID::SHA256 => {
                let mut mac = Hmac::<Sha256>::new_from_slice(key).map_err(|_| {
                    TpmError::InvalidArraySize("HMAC can take key of any size".to_string())
                })?;
                mac.update(to_hash);
                Ok(mac.finalize().into_bytes().to_vec())
            }
            TPM_ALG_ID::SHA384 => {
                let mut mac = Hmac::<Sha384>::new_from_slice(key).map_err(|_| {
                    TpmError::InvalidArraySize("HMAC can take key of any size".to_string())
                })?;
                mac.update(to_hash);
                Ok(mac.finalize().into_bytes().to_vec())
            }
            TPM_ALG_ID::SHA512 => {
                let mut mac = Hmac::<Sha512>::new_from_slice(key).map_err(|_| {
                    TpmError::InvalidArraySize("HMAC can take key of any size".to_string())
                })?;
                mac.update(to_hash);
                Ok(mac.finalize().into_bytes().to_vec())
            }
            TPM_ALG_ID::SM3_256 => {
                let mut mac =
                    Hmac::<Sm3>::new_from_slice(key).expect("HMAC can take key of any size");
                mac.update(to_hash);
                Ok(mac.finalize().into_bytes().to_vec())
            }
            _ => {
                return Err(TpmError::NotSupported(format!(
                    "Unsupported hash algorithm: {:?}",
                    hash_alg
                )))
            }
        }
    }

    pub fn validate_signature(
        public_key: &TPMT_PUBLIC,
        signed_blob_hash: Vec<u8>,
        signature: &Option<TPMU_SIGNATURE>,
    ) -> Result<bool, TpmError> {
        let rsa_params = if let Some(TPMU_PUBLIC_PARMS::rsaDetail(rsa_params)) = &public_key.parameters {
            rsa_params
        } else {
            return Err(TpmError::NotSupported(
                "ValidateSignature: Only RSA is supported".to_string(),
            ));
        };

        let signature = if let Some(TPMU_SIGNATURE::rsassa(signature)) = &signature {
            signature
        } else {
            return Err(TpmError::NotSupported(
                "ValidateSignature: Only RSASSA scheme is supported".to_string(),
            ));
        };

        let rsa_pub_key = if let Some(TPMU_PUBLIC_ID::rsa(unique)) = &public_key.unique {
            &unique.buffer
        } else {
            return Err(TpmError::NotSupported(
                "ValidateSignature: Only RSA public key is supported".to_string(),
            ));
        };

        let rsa_public_key = RsaPublicKey::new(BigUint::from_bytes_be(rsa_pub_key), BigUint::from_bytes_be(&[1, 0, 1]))
            .map_err(|_| TpmError::InvalidArraySize("Invalid RSA public key".to_string()))?;

        Ok(rsa_public_key
            .verify(
                Pkcs1v15Sign::new::<Sha1>(),
                &signed_blob_hash,
                &signature.sig
            ).is_ok())
    }
}
