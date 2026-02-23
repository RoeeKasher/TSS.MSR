use crate::crypto::Crypto;
use crate::error::TpmError;
use crate::{tpm_structure::TpmEnum, tpm_types::*};

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

    /// Derived session key (from KDFa with "ATH" label)
    pub session_key: Vec<u8>,

    /// Symmetric algorithm for parameter encryption
    pub symmetric: TPMT_SYM_DEF,
}

impl Session {
    pub fn new(
        session_handle: TPM_HANDLE,
        nonce_tpm: &[u8],
        session_attributes: TPMA_SESSION,
        nonce_caller: &[u8],
    ) -> Self {
        Session {
            sess_in: TPMS_AUTH_COMMAND::new(
                &session_handle,
                &nonce_caller.to_vec(),
                session_attributes,
                &Vec::new(),
            ),
            sess_out: TPMS_AUTH_RESPONSE::new(
                &nonce_tpm.to_vec(), 
                session_attributes,
                &Vec::new(),
            ),
            hash_alg: TPM_ALG_ID::SHA256,
            session_type: TPM_SE::HMAC,
            needs_hmac: true,
            needs_password: false,
            session_key: Vec::new(),
            symmetric: TPMT_SYM_DEF::default(),
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

    /// Create a fully initialized HMAC or policy session from a TPM StartAuthSession response.
    /// This mirrors the C++ AUTH_SESSION constructor + CalcSessionKey().
    pub fn from_tpm_response(
        session_handle: TPM_HANDLE,
        session_type: TPM_SE,
        hash_alg: TPM_ALG_ID,
        nonce_caller: Vec<u8>,
        nonce_tpm: Vec<u8>,
        attributes: TPMA_SESSION,
        symmetric: TPMT_SYM_DEF,
        salt: &[u8],
        bind_object: &TPM_HANDLE,
    ) -> Result<Self, TpmError> {
        let mut sess = Session {
            sess_in: TPMS_AUTH_COMMAND::new(
                &session_handle,
                &nonce_caller,
                attributes,
                &Vec::new(),
            ),
            sess_out: TPMS_AUTH_RESPONSE::new(
                &nonce_tpm,
                attributes,
                &Vec::new(),
            ),
            hash_alg,
            session_type,
            needs_hmac: session_type == TPM_SE::HMAC,
            needs_password: false,
            session_key: Vec::new(),
            symmetric,
        };

        sess.calc_session_key(salt, bind_object)?;
        Ok(sess)
    }

    /// Derive the session key using KDFa with label "ATH".
    /// SessionKey = KDFa(hashAlg, bindAuth || salt, "ATH", nonceTPM, nonceCaller, hashBits)
    fn calc_session_key(&mut self, salt: &[u8], bind_object: &TPM_HANDLE) -> Result<(), TpmError> {
        let null_handle = TPM_HANDLE::new(TPM_RH::NULL.get_value());
        let has_salt = !salt.is_empty();
        let is_bound = bind_object.handle != null_handle.handle;

        if !has_salt && !is_bound {
            // No key derivation needed for unbound, unsalted sessions
            return Ok(());
        }

        // hmacKey = bindAuth || salt
        let mut hmac_key = Vec::new();
        if is_bound {
            let bind_auth = trim_trailing_zeros(&bind_object.auth_value);
            hmac_key.extend_from_slice(&bind_auth);
        }
        hmac_key.extend_from_slice(salt);

        let hash_bits = Crypto::digestSize(self.hash_alg) * 8;
        self.session_key = Crypto::kdfa(
            self.hash_alg,
            &hmac_key,
            "ATH",
            &self.sess_out.nonce,  // nonceTPM
            &self.sess_in.nonce,   // nonceCaller
            hash_bits,
        )?;

        Ok(())
    }

    /// Check if this is a password authorization session
    pub fn is_pwap(&self) -> bool {
        self.sess_in.sessionHandle.handle == TPM_RH::PW.get_value()
    }

    /// Set authorization value for HMAC calculation
    pub fn set_auth_value(&mut self, auth_value: Vec<u8>) {
        if self.is_pwap() {
            self.sess_in.hmac = auth_value;
        }
    }

    /// Get the hash algorithm used by this session
    pub fn get_hash_alg(&self) -> TPM_ALG_ID {
        self.hash_alg
    }

    /// Generate an HMAC for authorization.
    /// hmacKey = sessionKey || authValue
    /// hmac = HMAC(hashAlg, hmacKey, parmHash || nonceNewer || nonceOlder || nonceDec || nonceEnc || sessionAttrs)
    pub fn get_auth_hmac(
        &self,
        cp_hash: Vec<u8>,
        is_command: bool,
        nonce_tpm_dec: &[u8],
        nonce_tpm_enc: &[u8],
        associated_handle: Option<&TPM_HANDLE>,
    ) -> Result<Vec<u8>, TpmError> {
        // PWAP: return the auth value directly
        if self.is_pwap() {
            return Ok(self.sess_in.hmac.clone());
        }

        // PolicyPassword: return auth value directly
        if self.needs_password {
            return Ok(self.sess_in.hmac.clone());
        }

        // Determine nonce order based on direction
        let (nonce_newer, nonce_older) = if is_command {
            (&self.sess_in.nonce, &self.sess_out.nonce)
        } else {
            (&self.sess_out.nonce, &self.sess_in.nonce)
        };

        // Session attributes as a single byte
        let session_attrs = vec![self.sess_in.sessionAttributes.get_value()];

        // Get auth value from the associated handle
        let mut auth = Vec::new();
        if let Some(handle) = associated_handle {
            // For HMAC sessions or policy sessions that need HMAC
            if self.session_type != TPM_SE::POLICY || self.needs_hmac {
                auth = trim_trailing_zeros(&handle.auth_value);
            }
        }

        // hmacKey = sessionKey || auth
        let mut hmac_key = Vec::new();
        hmac_key.extend_from_slice(&self.session_key);
        hmac_key.extend_from_slice(&auth);

        // Buffer to HMAC: parmHash || nonceNewer || nonceOlder || nonceDec || nonceEnc || sessionAttrs
        let mut buf_to_hmac = Vec::new();
        buf_to_hmac.extend_from_slice(&cp_hash);
        buf_to_hmac.extend_from_slice(nonce_newer);
        buf_to_hmac.extend_from_slice(nonce_older);
        buf_to_hmac.extend_from_slice(nonce_tpm_dec);
        buf_to_hmac.extend_from_slice(nonce_tpm_enc);
        buf_to_hmac.extend_from_slice(&session_attrs);

        Crypto::hmac(self.hash_alg, &hmac_key, &buf_to_hmac)
    }

    /// Process parameter encryption/decryption using KDFa-derived XOR mask or AES-CFB.
    pub fn param_xcrypt(&self, data: &[u8], _is_encrypt: bool) -> Vec<u8> {
        // TODO: Implement proper AES-CFB parameter encryption
        // For now, pass data through unchanged (works for unencrypted sessions)
        data.to_vec()
    }
}

/// Trim trailing zero bytes from a byte vector
fn trim_trailing_zeros(data: &[u8]) -> Vec<u8> {
    let mut result = data.to_vec();
    while result.last() == Some(&0) {
        result.pop();
    }
    result
}
