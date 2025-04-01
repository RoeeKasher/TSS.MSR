use crate::crypto::Crypto;
use crate::error::TpmError;
use crate::tpm2_helpers::int_to_tpm;
use crate::tpm_buffer::*;
use crate::tpm_structure::TpmEnum;
use crate::tpm_types::CertifyResponse;
use crate::tpm_types::*;

impl TPMT_PUBLIC {
    pub fn get_name(&self) -> Result<Vec<u8>, TpmError> {
        let mut buffer = TpmBuffer::new(None);
        self.toTpm(&mut buffer)?;
        
        let mut pub_hash = Crypto::hash(self.nameAlg, buffer.trim())?;
        let hash_alg = int_to_tpm(self.nameAlg.get_value());
        
        pub_hash.splice(0..0, hash_alg.iter().cloned());

        Ok(pub_hash)
    }

    pub fn get_signing_hash_alg(&self) -> Result<TPM_ALG_ID, TpmError> {
        let rsa_params = if let Some(TPMU_PUBLIC_PARMS::rsaDetail(rsa_params)) = &self.parameters {
            rsa_params
        } else {
            return Err(TpmError::NotSupported(
                "Get signing hash algorithm is only supported for RSA".to_string(),
            ));
        };

        let scheme = if let Some(TPMU_ASYM_SCHEME::rsassa(scheme)) = &rsa_params.scheme {
            scheme
        } else {
            return Err(TpmError::NotSupported(
                "Get signing hash algorithm is only supported for RSA-SSA".to_string(),
            ));
        };

        Ok(scheme.hashAlg)
    }

    pub fn validate_certify(&self, certified_key: &TPMT_PUBLIC, nonce: &[u8], certify_response: &CertifyResponse) -> Result<bool, TpmError> {
        let hash_alg = self.get_signing_hash_alg()?;
        let attest = &certify_response.certifyInfo;

        if (attest.extraData != nonce) {
            return Ok(false);
        }

        if (attest.magic != TPM_GENERATED::VALUE) {
            return Ok(false);
        }

        if let Some(TPMU_ATTEST::certify(quote_info)) = &attest.attested {
            if (quote_info.name != certified_key.get_name()?) {
                return Ok(false);
            }
        } else {
            return Ok(false);
        }

        // And finally check the signature
        let signed_blob = { 
            let mut buffer = TpmBuffer::new(None);
            certify_response.certifyInfo.toTpm(&mut buffer)?;
            buffer.trim().to_vec()
        };

        let signed_blob_hash = Crypto::hash(hash_alg, &signed_blob)?;

        Crypto::validate_signature(self, signed_blob_hash, &certify_response.signature)
    }
}