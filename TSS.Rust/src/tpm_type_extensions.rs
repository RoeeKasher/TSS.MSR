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

    pub fn validate_certify(
        &self,
        certified_key: &TPMT_PUBLIC,
        nonce: &[u8],
        certify_response: &CertifyResponse,
    ) -> Result<bool, TpmError> {
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

        // And finally, check the signature
        let signed_blob = {
            let mut buffer = TpmBuffer::new(None);
            certify_response.certifyInfo.toTpm(&mut buffer)?;
            buffer.trim().to_vec()
        };

        let signed_blob_hash = Crypto::hash(hash_alg, &signed_blob)?;

        Crypto::validate_signature(self, signed_blob_hash, &certify_response.signature)
    }
}

impl TPMS_PCR_SELECTION {
    /// Get a PCR-selection array naming exactly one PCR in one bank
    pub fn get_selection_array(hash_alg: TPM_ALG_ID, pcr: u32) -> Vec<Self> {
        vec![TPMS_PCR_SELECTION::new_from_pcr_u32(hash_alg, pcr)]
    }

    /// Create a TPMS_PCR_SELECTION naming a single-PCR
    pub fn new_from_pcr_u32(hash_alg: TPM_ALG_ID, pcr: u32) -> Self {
        let mut size = 3;

        let pcr_bytes = pcr / 8;
        if ((pcr_bytes / 8) + 1) > size {
            size = pcr_bytes + 1;
        }

        let mut pcr_select = vec![0; size as usize];
        pcr_select[pcr_bytes as usize] = 1 << (pcr % 8);

        TPMS_PCR_SELECTION::new(hash_alg, &pcr_select)
    }

    /// Create a TPMS_PCR_SELECTION for a set of PCRs in a single bank
    pub fn new_from_pcrs_vec(hash_alg: TPM_ALG_ID, pcrs: &[u32]) -> Self {
        let mut pcr_max = *pcrs.iter().max().unwrap_or(&0);

        if (pcr_max < 23) {
            pcr_max = 23;
        }

        let mut pcr_select = vec![0; (pcr_max / 8 + 1) as usize];
        for pcr in pcrs {
            pcr_select[*pcr as usize / 8] |= 1 << (*pcr % 8);
        }

        TPMS_PCR_SELECTION::new(hash_alg, &pcr_select)
    }
}

impl TPM_HANDLE {
    /// Creates a handle for a persistent object
    pub fn persistent(handle_offset: u32) -> Self {
        Self::new(((TPM_HT::PERSISTENT.get_value() as u32) << 24) + handle_offset)
    }

    /// Creates a handle for a PCR
    pub fn pcr(pcr_index: u32) -> Self {
        Self::new(pcr_index)
    }

    /// Creates a handle for an NV slot
    pub fn nv(nv_index: u32) -> Self {
        Self::new(((TPM_HT::NV_INDEX.get_value() as u32) << 24) + nv_index)
    }

    /// Set the authorization value for this TPM_HANDLE.  The default auth-value is NULL
    pub fn set_auth(&mut self, auth_val: &[u8]) {
        self.auth_value = auth_val.to_vec();
    }

    /// Returns this handle's type
    pub fn get_type(&self) -> TPM_HT {
        // The handle type is the top byte of the handle value
        unsafe { std::mem::transmute((self.handle >> 24) as u8) }
    }

    pub fn set_name(&mut self, name: &[u8]) -> Result<(), TpmError> {
        let handle_type = self.get_type();

        if (handle_type == TPM_HT::NV_INDEX
            || handle_type == TPM_HT::TRANSIENT
            || handle_type == TPM_HT::PERSISTENT
            || handle_type == TPM_HT::PERSISTENT)
        {
            self.name = name.to_vec();
            return Ok(());
        }

        if (name != self.get_name()?) {
            return Err(TpmError::GenericError(format!("Setting an invalid name of an entity with the name defined by the handle value, handle type: {}", handle_type)));
        }

        Ok(())
    }

    /// Get the TPM name of this handle
    pub fn get_name(&self) -> Result<Vec<u8>, TpmError> {
        let handle_type = self.get_type();

        // Per spec: handles of these types have their handle value as their name
        if handle_type == TPM_HT::PCR
            || handle_type == TPM_HT::HMAC_SESSION
            || handle_type == TPM_HT::POLICY_SESSION
            || handle_type == TPM_HT::PERMANENT
        {
            let mut name = Vec::with_capacity(4);
            name.extend_from_slice(&self.handle.to_be_bytes());
            return Ok(name);
        }

        if handle_type == TPM_HT::NV_INDEX
            || handle_type == TPM_HT::TRANSIENT
            || handle_type == TPM_HT::PERSISTENT
        {
            if (self.name.is_empty()) {
                return Err(TpmError::GenericError(format!(
                    "Name is not set for handle, handle type: {}",
                    handle_type
                )));
            }
            return Ok(self.name.clone());
        }

        Err(TpmError::GenericError(format!(
            "Unknown handle type, handle type: {}",
            handle_type
        )))
    }

    /// Get a string representation of this handle
    pub fn to_string(&self) -> String {
        format!("{}:0x{:x}", self.get_type(), self.handle)
    }
}
