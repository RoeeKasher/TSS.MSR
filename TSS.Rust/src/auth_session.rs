use crate::{tpm_structure::TpmEnum, tpm_types::*};

/// Authentication session for TPM commands
#[derive(Debug, Default)]
pub struct Session {
    pub sess_in: TPMS_AUTH_COMMAND,

    pub sess_out: TPMS_AUTH_RESPONSE,
}

impl Session {
    pub fn new(sessionHandle: TPM_HANDLE,
                nonceTpm: &[u8],
                sessionAttributes: TPMA_SESSION,
                nonceCaller: &[u8]) -> Self {
        Session {
            sess_in: TPMS_AUTH_COMMAND::new(sessionHandle, nonceCaller.to_vec(), sessionAttributes, Vec::new()),
            sess_out: TPMS_AUTH_RESPONSE::new(nonceTpm.to_vec(), sessionAttributes, Vec::new()),
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
     
        s
    }
}