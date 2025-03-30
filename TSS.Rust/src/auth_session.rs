use crate::{tpm_structure::TpmEnum, tpm_types::*};
use crate::crypto::Crypto;

/// Authentication session for TPM commands
#[derive(Debug, Default, Clone)]
pub struct Session {
    pub sess_in: TPMS_AUTH_COMMAND,
    pub sess_out: TPMS_AUTH_RESPONSE,
    
    // Additional session properties
    pub hash_alg: TPM_ALG_ID,
    pub session_type: TPM_SE,
    pub needs_hmac: bool,
    pub needs_password: bool,
}

impl Session {
    pub fn new(session_handle: TPM_HANDLE,
                nonce_tpm: &[u8],
                session_attributes: TPMA_SESSION,
                nonce_caller: &[u8]) -> Self {
        Session {
            sess_in: TPMS_AUTH_COMMAND::new(session_handle, nonce_caller.to_vec(), session_attributes, Vec::new()),
            sess_out: TPMS_AUTH_RESPONSE::new(nonce_tpm.to_vec(), session_attributes, Vec::new()),
            hash_alg: TPM_ALG_ID::SHA256, // Default
            session_type: TPM_SE::HMAC,   // Default
            needs_hmac: true,
            needs_password: false,
        }
    }

    /// Create a password authorization session (PWAP)
    pub fn pw(auth_value: Option<Vec<u8>>) -> Self {
        let mut s = Session::default();
        s.sess_in.sessionHandle = TPM_HANDLE::new(TPM_RH::PW.get_value());
        s.sess_in.nonce = Vec::new();
        s.sess_in.sessionAttributes = TPMA_SESSION::continueSession;
        let auth_value = auth_value.unwrap_or_default();
        s.sess_in.hmac = auth_value;
        s.sess_out.sessionAttributes = TPMA_SESSION::continueSession;
        s.session_type = TPM_SE::HMAC;
        s.needs_hmac = false;
        s.needs_password = true;
        
        s
    }
    
    /// Check if this is a password authorization session
    pub fn is_pwap(&self) -> bool {
        self.sess_in.sessionHandle.get_value() == TPM_RH::PW.get_value()
    }
    
    /// Set authorization value for HMAC calculation
    pub fn set_auth_value(&mut self, auth_value: Vec<u8>) {
        // In PWAP sessions, this directly sets the HMAC
        if self.is_pwap() {
            self.sess_in.hmac = auth_value;
        }
        // Otherwise, store for later HMAC calculation
    }
    
    /// Get the hash algorithm used by this session
    pub fn get_hash_alg(&self) -> TPM_ALG_ID {
        self.hash_alg
    }
    
    /// Generate an HMAC for authorization
    pub fn get_auth_hmac(&self, 
                         cp_hash: Vec<u8>,
                         is_command: bool, 
                         nonce_tpm_dec: &[u8], 
                         nonce_tpm_enc: &[u8],
                         associated_handle: Option<&TPM_HANDLE>) -> Vec<u8> {
        // This is a simplified implementation
        // In a real implementation this would properly compute the HMAC
        
        // For PWAP sessions just return the auth value
        if self.is_pwap() && associated_handle.is_some() {
            return associated_handle.unwrap().get_auth();
        }
        
        // For now return empty HMAC
        Vec::new()
    }
    
    /// Process parameter encryption/decryption
    pub fn param_xcrypt(&self, data: &[u8], is_encrypt: bool) -> Vec<u8> {
        // This is a placeholder implementation
        // In a real implementation this would properly encrypt/decrypt the parameter
        data.to_vec()
    }
}