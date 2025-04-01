/*
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See the LICENSE file in the project root for full license information.
 */

use crate::auth_session::Session;
use crate::crypto::Crypto;
use crate::device::TpmDevice;
use crate::error::TpmError;
use crate::tpm_buffer::{TpmBuffer, TpmMarshaller};
use crate::tpm_structure::{ReqStructure, RespStructure, TpmEnum, TpmStructure};
use crate::tpm_types::{
    TPMA_SESSION, TPMS_AUTH_COMMAND, TPMS_AUTH_RESPONSE, TPMT_HA, TPM_ALG_ID, TPM_CC, TPM_HANDLE,
    TPM_HT, TPM_RC, TPM_RH, TPM_SE, TPM_ST,
};

/// A TPM error with associated command and context information
#[derive(Debug, Clone)]
pub struct TpmCommandError {
    /// Response code returned by the TPM
    pub response_code: TPM_RC,
    /// Command code that triggered the error
    pub command_code: TPM_CC,
    /// Description of the error
    pub message: String,
}

impl std::fmt::Display for TpmCommandError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "TPM command {:?} failed with response code {:?}: {}",
            self.command_code, self.response_code, self.message
        )
    }
}

impl std::error::Error for TpmCommandError {}

impl From<TpmCommandError> for TpmError {
    fn from(err: TpmCommandError) -> Self {
        TpmError::GenericError(err.to_string())
    }
}

/// Base implementation for TPM operations
pub struct Tpm2 {
    /// The TPM device used for communication
    device: Box<dyn TpmDevice>,

    /// Response code returned by the last executed command
    last_response_code: TPM_RC,

    /// Error object (may be None) generated during the last TPM command execution
    last_error: Option<TpmCommandError>,

    /// TPM sessions associated with the next command
    sessions: Option<Vec<Session>>,

    /// Controls whether exceptions are enabled
    exceptions_enabled: bool,

    /// Suppresses exceptions in response to the next command failure, when exceptions are enabled
    errors_allowed: bool,

    /// Command code for the current operation (for error reporting)
    current_cmd_code: Option<TPM_CC>,

    /// Session tag for the current operation
    current_session_tag: Option<TPM_ST>,

    /// Handle for pending TPM commands
    pending_command: Option<TPM_CC>,

    /// Input handles for current command
    in_handles: Vec<TPM_HANDLE>,

    /// Auth value for objects
    object_in_auth: Vec<u8>,

    /// Name for objects
    object_in_name: Vec<u8>,

    /// Admin authorization handles with auth values
    admin_platform: TPM_HANDLE,
    admin_owner: TPM_HANDLE,
    admin_endorsement: TPM_HANDLE,
    admin_lockout: TPM_HANDLE,

    /// CpHash for parameter encryption
    cp_hash: Option<TPMT_HA>,

    /// Command audit hash
    command_audit_hash: TPMT_HA,

    /// Audit command flag
    audit_command: bool,

    /// Audit CpHash
    audit_cp_hash: TPMT_HA,

    /// Encryption session
    enc_session: Option<Session>,

    /// Decryption session
    dec_session: Option<Session>,

    /// Nonces for TPM parameter encryption/decryption
    nonce_tpm_dec: Vec<u8>,
    nonce_tpm_enc: Vec<u8>,

    /// Command buffer for last command
    last_command_buf: Vec<u8>,
}

impl Tpm2 {
    /// Creates a new Tpm2 with the specified device
    pub fn new(device: Box<dyn TpmDevice>) -> Self {
        Tpm2 {
            device,
            last_response_code: TPM_RC::SUCCESS,
            last_error: None,
            sessions: None,
            exceptions_enabled: false,
            errors_allowed: true,
            current_cmd_code: None,
            current_session_tag: None,
            pending_command: None,
            in_handles: Vec::new(),
            object_in_auth: Vec::new(),
            object_in_name: Vec::new(),
            admin_platform: TPM_HANDLE::new(0),
            admin_owner: TPM_HANDLE::new(0),
            admin_endorsement: TPM_HANDLE::new(0),
            admin_lockout: TPM_HANDLE::new(0),
            cp_hash: None,
            command_audit_hash: TPMT_HA::default(),
            audit_command: false,
            audit_cp_hash: TPMT_HA::default(),
            enc_session: None,
            dec_session: None,
            nonce_tpm_dec: Vec::new(),
            nonce_tpm_enc: Vec::new(),
            last_command_buf: Vec::new(),
        }
    }

    /// Checks whether the response code is generated by the TSS.Rust implementation
    fn is_comm_medium_error(code: TPM_RC) -> bool {
        // Check if error is in the TSS communication layer rather than TPM itself
        (code.get_value()) & 0xFFFF0000 == 0x80280000
    }

    /// Cleans the raw response code from the TPM
    fn response_code_from_tpm_error(raw_response: TPM_RC) -> TPM_RC {
        if Self::is_comm_medium_error(raw_response) {
            return raw_response;
        }

        let raw_response_u32 = raw_response.get_value();
        let is_fmt = (raw_response_u32 & TPM_RC::RC_FMT1.get_value()) != 0;


        let mask: u32 = if is_fmt { 0xBF } else { 0x97F };

        TPM_RC { 0: (raw_response_u32 & mask) }
    }

    /// Generates an error response buffer
    fn generate_error_response(&self, rc: TPM_RC) -> TpmBuffer {
        let mut resp_buf = TpmBuffer::new(None);
        resp_buf.writeShort(TPM_ST::NO_SESSIONS.get_value() as u16);
        resp_buf.writeInt(10);
        resp_buf.writeInt(rc.get_value());
        resp_buf
    }

    /// Generates an error based on the response code
    fn generate_error(
        &mut self,
        resp_code: TPM_RC,
        err_msg: &str,
        errors_allowed: bool,
    ) -> Result<(), TpmCommandError> {
        let cmd_code = self.current_cmd_code.unwrap_or(TPM_CC::FIRST);
        let error = TpmCommandError {
            response_code: resp_code,
            command_code: cmd_code,
            message: err_msg.to_string(),
        };

        println!("Generating error: {:?}", error);

        self.last_error = Some(error.clone());

        if self.exceptions_enabled && !errors_allowed {
            Err(error)
        } else {
            Ok(())
        }
    }

    /// Send a TPM command to the underlying TPM device.
    pub fn dispatch<R: ReqStructure, S: RespStructure>(
        &mut self,
        cmd_code: TPM_CC,
        req: R,
        resp: &mut S,
    ) -> Result<(), TpmError> {
        loop {
            let process_phase_two: bool = self.dispatch_command(cmd_code, &req)?;
            if (!process_phase_two || self.process_response(cmd_code, resp)?) {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(1000));
        }

        Ok(())
    }

    /// Internal method to dispatch a command to the TPM
    /// Matches the C++ DispatchOut function
    pub fn dispatch_command<R: ReqStructure>(
        &mut self,
        cmd_code: TPM_CC,
        req: &R,
    ) -> Result<(bool), TpmError> {
        if self.current_cmd_code.is_some() {
            return Err(TpmError::GenericError(
                "Pending async command must be completed before issuing the next command."
                    .to_string(),
            ));
        }

        if self.audit_command && self.command_audit_hash.hashAlg == TPM_ALG_ID::NULL {
            return Err(TpmError::GenericError(
                "Command audit is not enabled".to_string(),
            ));
        }

        self.current_cmd_code = Some(cmd_code);

        // Determine session tag based on whether we need authorization
        let num_auth_handles = req.num_auth_handles();
        let has_sessions = num_auth_handles > 0 || self.sessions.is_some();
        self.current_session_tag = if has_sessions {
            Some(TPM_ST::SESSIONS)
        } else {
            Some(TPM_ST::NO_SESSIONS)
        };

        let mut cmd_buf = TpmBuffer::new(None);

        // Create command buffer header
        cmd_buf.writeShort(self.current_session_tag.unwrap().get_value() as u16);
        cmd_buf.writeInt(0); // to be filled in later
        cmd_buf.writeInt(cmd_code.get_value());

        // Marshal handles
        self.in_handles = req.get_handles();
        for handle in self.in_handles.iter() {
            handle.toTpm(&mut cmd_buf)?;
        }

        // Marshal command parameters to a separate buffer
        let mut param_buf = TpmBuffer::new(None);
        req.toTpm(&mut param_buf)?;
        param_buf.trim();

        // Process authorization sessions if present
        let mut cp_hash_data = Vec::new();

        if has_sessions {
            // We do not know the size of the authorization area yet.
            // Remember the place to marshal it, ...
            let auth_size_pos = cmd_buf.current_pos();
            // ... and marshal a placeholder 0 value for now.
            cmd_buf.writeInt(0);

            // If not all required sessions were provided explicitly, create the necessary
            // number of password sessions with auth values from the corresponding TPM_HANDLE objects.
            if let Some(ref mut sessions) = self.sessions {
                // Ensure we have enough sessions
                if sessions.len() < num_auth_handles as usize {
                    for _ in sessions.len()..(num_auth_handles as usize) {
                        sessions.push(Session::pw(None));
                    }
                }

                // Roll nonces
                self.roll_nonces();

                // Prepare parameter encryption sessions
                self.prepare_param_encryption_sessions();

                // Do parameter encryption if needed
                self.do_param_encryption(req, &mut param_buf, 0, true)?;

                // Process authorization sessions and get cpHash data
                cp_hash_data = self.process_auth_sessions(
                    &mut cmd_buf,
                    cmd_code,
                    num_auth_handles,
                    &param_buf.buffer(),
                )?;
            } else {
                // Create all password sessions
                let mut new_sessions = Vec::with_capacity(num_auth_handles as usize);
                for _ in 0..num_auth_handles {
                    new_sessions.push(Session::pw(None));
                }

                // Marshal sessions to command buffer
                for sess in new_sessions.iter() {
                    sess.sess_in.toTpm(&mut cmd_buf)?;
                }

                self.sessions = Some(new_sessions);
            }

            // Update the auth area size
            cmd_buf.write_num_at_pos(
                (cmd_buf.current_pos() - auth_size_pos - 4) as u64,
                auth_size_pos,
                4,
            );
        }

        // Write marshaled command params to the command buffer
        cmd_buf.writeByteBuf(&param_buf.buffer());

        // Fill in command buffer size in the command header
        cmd_buf.write_num_at_pos(cmd_buf.current_pos() as u64, 2, 4);
        cmd_buf.trim();

        // Handle CpHash and Audit processing
        if self.cp_hash.is_some() || self.audit_command {
            if cp_hash_data.is_empty() {
                cp_hash_data = self.get_cp_hash_data(cmd_code, &param_buf.buffer())?;
            }

            if let Some(ref mut cp_hash) = self.cp_hash {
                cp_hash.digest = Crypto::hash(cp_hash.hashAlg, &cp_hash_data)?;
                self.clear_invocation_state();
                self.sessions = None;
                self.cp_hash = None;
                return Ok(false);
            }

            if self.audit_command {
                self.audit_cp_hash.digest =
                    Crypto::hash(self.command_audit_hash.hashAlg, &cp_hash_data)?;
            }
        }

        // Dispatch command to the device
        self.last_command_buf = cmd_buf.trim().to_vec();
        self.device.dispatch_command(&self.last_command_buf)?;

        // Update request handles based on command
        self.update_request_handles(cmd_code, req)?;

        // Set pending command
        self.pending_command = Some(cmd_code);

        Ok(true)
    }

    /// Process the TPM response and update the response structure
    /// Matches the C++ DispatchIn function
    pub fn process_response<T: RespStructure>(
        &mut self,
        cmd_code: TPM_CC,
        resp_struct: &mut T,
    ) -> Result<(bool), TpmError> {
        if self.pending_command.is_none() {
            return Err(TpmError::GenericError(
                "Async command completion with no outstanding command".to_string(),
            ));
        }

        if self.pending_command.unwrap() != cmd_code {
            return Err(TpmError::GenericError(
                "Async command completion does not match command being processed".to_string(),
            ));
        }

        if self.audit_command && self.command_audit_hash.hashAlg == TPM_ALG_ID::NULL {
            return Err(TpmError::GenericError(
                "Command audit is not enabled".to_string(),
            ));
        }

        self.pending_command = None;

        // Get response from the TPM device
        let raw_resp_buf = self.device.get_response()?;

        if raw_resp_buf.len() < 10 {
            return Err(TpmError::GenericError(format!(
                "Too short TPM response of {} B received",
                raw_resp_buf.len()
            )));
        }

        let mut resp_buf = TpmBuffer::from(&raw_resp_buf);

        // Read the response header
        let resp_tag = TPM_ST::try_from(resp_buf.readShort())?;
        let resp_size = resp_buf.readInt();
        let resp_code = TPM_RC::try_from(resp_buf.readInt())?;

        let act_resp_size = resp_buf.size();
        if resp_size as usize != act_resp_size {
            return Err(TpmError::GenericError(format!(
                "Inconsistent TPM response buffer: {} B reported, {} B received",
                resp_size, act_resp_size
            )));
        }

        if resp_code == TPM_RC::RETRY {
            return Ok(false);
        }

        // Clean and store the response code
        self.last_response_code = Self::response_code_from_tpm_error(resp_code);

        // Figure out our reaction to the received response. This logic depends on:
        //   errors_allowed - no exception, regardless of success or failure
        //
        // We'll implement error handling here similar to C++ version

        // Store a copy of audit command flag before clearing invocation state
        let audit_command = self.audit_command;

        // Handle errors and clean up invocation state
        if resp_code != TPM_RC::SUCCESS {
            self.clear_invocation_state();
            self.sessions = None;

            // Return error
            return Err(TpmError::GenericError(format!(
                "TPM Error - TPM_RC::{:?}",
                self.last_response_code
            )));
        }

        // A check for the session tag consistency across the command invocation
        let sess_tag = self.current_session_tag.unwrap_or(TPM_ST::NULL);
        if resp_tag != sess_tag {
            self.clear_invocation_state();
            self.sessions = None;
            return Err(TpmError::GenericError(
                "Wrong response session tag".to_string(),
            ));
        }

        //
        // The command succeeded, so we can process the response buffer
        //

        // Get the handles if any
        if resp_struct.num_handles() > 0 {
            let handle_val = resp_buf.readInt();
            resp_struct.set_handle(&TPM_HANDLE::new(handle_val));
        }

        let mut resp_params_pos = 0;
        let mut resp_params_size = 0;
        let mut rp_ready = false;

        // If there are no sessions then response parameters take up the remaining part
        // of the response buffer. Otherwise the response parameters area is preceded with
        // its size, and followed by the session area.
        if sess_tag == TPM_ST::SESSIONS {
            resp_params_size = resp_buf.readInt() as usize;
            resp_params_pos = resp_buf.current_pos();

            // Process response sessions, including verification of response HMACs
            rp_ready = match self.process_resp_sessions(
                &mut resp_buf,
                cmd_code,
                resp_params_pos,
                resp_params_size,
            ) {
                Ok(ready) => ready,
                Err(e) => {
                    self.clear_invocation_state();
                    self.sessions = None;
                    return Err(e);
                }
            };
        } else {
            resp_params_pos = resp_buf.current_pos();
            resp_params_size = resp_buf.size() - resp_params_pos;
        }

        // Handle audit processing
        if audit_command {
            let rp_hash = self.get_rp_hash(
                self.command_audit_hash.hashAlg,
                &mut resp_buf,
                cmd_code,
                resp_params_pos,
                resp_params_size,
                rp_ready,
            );

            // TODO: Implement this
            // Equivalent of CommandAuditHash.Extend(Helpers::Concatenate(AuditCpHash, rpHash))
            // In a real implementation, this would properly extend the audit digest with both hash values
        }

        // Parameter decryption (if necessary)
        if let Err(e) = self.do_param_encryption(resp_struct, &mut resp_buf, resp_params_pos, false)
        {
            self.clear_invocation_state();
            self.sessions = None;
            return Err(e);
        }

        // Reset position to start of parameters area and unmarshall
        resp_buf.set_current_pos(resp_params_pos);
        resp_struct.initFromTpm(&mut resp_buf)?;

        // Validate that we read the exact number of bytes expected
        if resp_buf.current_pos() != resp_params_pos + resp_params_size {
            self.clear_invocation_state();
            self.sessions = None;
            return Err(TpmError::GenericError(
                "Bad response parameters area".to_string(),
            ));
        }

        // Update response handle with name and auth value
        if let Err(e) = self.update_resp_handle(cmd_code, resp_struct) {
            self.clear_invocation_state();
            self.sessions = None;
            return Err(e);
        }

        // Clear sessions and return success
        self.sessions = None;
        self.clear_invocation_state();

        Ok(true)
    }
}

impl Tpm2 {
    fn last_response_code(&self) -> TPM_RC {
        self.last_response_code
    }

    fn last_error(&self) -> Option<TpmCommandError> {
        self.last_error.clone()
    }

    fn allow_errors(&mut self) -> &mut Self {
        self.errors_allowed = true;
        self
    }

    fn enable_exceptions(&mut self, enable: bool) {
        self.exceptions_enabled = enable;
        self.errors_allowed = !enable;
    }

    fn with_session(&mut self, session: Session) -> &mut Self {
        self.sessions = Some(vec![session]);
        self
    }

    fn with_sessions(&mut self, sessions: Vec<Session>) -> &mut Self {
        self.sessions = Some(sessions);
        self
    }

    fn connect(&mut self) -> Result<(), TpmError> {
        self.device.connect()?;
        self.last_response_code = TPM_RC::SUCCESS;
        Ok(())
    }

    fn close(&mut self) {
        self.device.close();
    }
}

impl Tpm2 {
    // Additional helper methods to support the dispatch_command and process_response implementations

    /// Roll nonces for all non-PWAP sessions
    fn roll_nonces(&mut self) {
        if let Some(ref mut sessions) = self.sessions {
            for session in sessions.iter_mut() {
                if !session.is_pwap() {
                    // Generate random nonce for the caller
                    // In a real implementation, use proper random number generation
                    let nonce_size = session.sess_out.nonce.len();
                    session.sess_in.nonce = vec![0; nonce_size]; // Replace with real random data
                }
            }
        }
    }

    /// Clear the current invocation state
    fn clear_invocation_state(&mut self) {
        self.current_cmd_code = None;
        self.current_session_tag = None;
        // Clear other command-specific state
    }

    /// Set RH (resource handle) auth value for admin handles
    fn set_rh_auth_value(&self, h: &mut TPM_HANDLE) {
        match h.handle {
            val if val == TPM_RH::OWNER.get_value() => h.set_auth(&self.admin_owner.auth_value),
            val if val == TPM_RH::ENDORSEMENT.get_value() => {
                h.set_auth(&self.admin_endorsement.auth_value)
            }
            val if val == TPM_RH::PLATFORM.get_value() => {
                h.set_auth(&self.admin_platform.auth_value)
            }
            val if val == TPM_RH::LOCKOUT.get_value() => h.set_auth(&self.admin_lockout.auth_value),
            _ => {} // No auth value change needed
        }
    }

    /// Get CpHash data for parameter encryption
    fn get_cp_hash_data(&self, cmd_code: TPM_CC, cmd_params: &[u8]) -> Result<Vec<u8>, TpmError> {
        let mut buf = TpmBuffer::new(None);
        buf.writeInt(cmd_code.get_value());

        for h in self.in_handles.iter() {
            let name = h.get_name()?;
            buf.writeByteBuf(&name);
        }

        buf.writeByteBuf(&cmd_params.to_vec());
        Ok(buf.buffer().clone())
    }

    /// Process authorization sessions for a command
    fn process_auth_sessions(
        &mut self,
        cmd_buf: &mut TpmBuffer,
        cmd_code: TPM_CC,
        num_auth_handles: u16,
        cmd_params: &[u8],
    ) -> Result<Vec<u8>, TpmError> {
        let mut needs_hmac = false;

        if let Some(ref sessions) = self.sessions {
            for session in sessions.iter() {
                if !session.is_pwap() {
                    needs_hmac = true;
                    break;
                }
            }
        }

        // Compute CpHash if needed for HMAC sessions
        let cp_hash_data = if needs_hmac {
            self.get_cp_hash_data(cmd_code, cmd_params)?
        } else {
            Vec::new()
        };

        if let Some(ref mut sessions) = self.sessions {
            for (i, session) in sessions.iter().enumerate() {
                let mut auth_cmd = TPMS_AUTH_COMMAND::default();

                // If it's a PWAP session, handling is simple
                if session.is_pwap() {
                    auth_cmd.sessionHandle = TPM_HANDLE::new(TPM_RH::PW.get_value());
                    auth_cmd.nonce = Vec::new();

                    if i < self.in_handles.len() {
                        auth_cmd.hmac = self.in_handles[i].auth_value.clone();
                    }

                    auth_cmd.sessionAttributes = TPMA_SESSION::continueSession;
                    auth_cmd.toTpm(cmd_buf)?;
                    continue;
                }

                // For non-PWAP sessions, we need more complex processing
                let mut h_copy = None;

                if i < num_auth_handles as usize {
                    if i < self.in_handles.len() {
                        // Set appropriate auth value on handle
                        h_copy = Some(self.in_handles[i].clone());
                    }
                }

                auth_cmd.nonce = session.sess_in.nonce.clone();
                auth_cmd.sessionHandle = session.sess_in.sessionHandle.clone();
                auth_cmd.sessionAttributes = session.sess_in.sessionAttributes;

                if session.session_type == TPM_SE::HMAC || session.needs_hmac {
                    // Calculate HMAC based on CpHash
                    let cp_hash = Crypto::hash(session.get_hash_alg(), &cp_hash_data)?;
                    auth_cmd.hmac = session.get_auth_hmac(
                        cp_hash,
                        true,
                        &self.nonce_tpm_dec,
                        &self.nonce_tpm_enc,
                        h_copy.as_ref(),
                    )?;
                } else if session.needs_password {
                    auth_cmd.hmac = self.in_handles[i].auth_value.clone();
                }

                auth_cmd.toTpm(cmd_buf)?;
            }
        }

        Ok(cp_hash_data)
    }

    /// Prepare parameter encryption sessions
    fn prepare_param_encryption_sessions(&mut self) {
        self.enc_session = None;
        self.dec_session = None;
        self.nonce_tpm_dec.clear();
        self.nonce_tpm_enc.clear();

        if let Some(ref sessions) = self.sessions {
            for session in sessions.iter() {
                if session.is_pwap() {
                    continue;
                }

                // Check for decrypt attribute
                if (session.sess_in.sessionAttributes.get_value()
                    & TPMA_SESSION::decrypt.get_value())
                    != 0
                {
                    self.dec_session = Some(session.clone());
                }

                // Check for encrypt attribute
                if (session.sess_in.sessionAttributes.get_value()
                    & TPMA_SESSION::encrypt.get_value())
                    != 0
                {
                    self.enc_session = Some(session.clone());
                }
            }

            // Store nonces for the first session to prevent tampering
            if let Some(ref sessions_vec) = self.sessions {
                if !sessions_vec.is_empty() {
                    let first_session = &sessions_vec[0];

                    // If first session is followed by decrypt session
                    if let Some(ref dec) = self.dec_session {
                        if dec.sess_in.sessionHandle.handle
                            != first_session.sess_in.sessionHandle.handle
                        {
                            self.nonce_tpm_dec = dec.sess_out.nonce.clone();
                        }
                    }

                    // If first session is followed by encrypt session (and it's not the decrypt session)
                    if let Some(ref enc) = self.enc_session {
                        if enc.sess_in.sessionHandle.handle
                            != first_session.sess_in.sessionHandle.handle
                            && (self.dec_session.is_none()
                                || enc.sess_in.sessionHandle.handle
                                    != self
                                        .dec_session
                                        .as_ref()
                                        .unwrap()
                                        .sess_in
                                        .sessionHandle
                                        .handle)
                        {
                            self.nonce_tpm_enc = enc.sess_out.nonce.clone();
                        }
                    }
                }
            }
        }
    }

    /// Process parameter encryption/decryption
    fn do_param_encryption<T: TpmStructure>(
        &self,
        cmd: &T,
        param_buf: &mut TpmBuffer,
        start_pos: usize,
        is_request: bool,
    ) -> Result<(), TpmError> {
        let xcrypt_sess = if is_request {
            if self.dec_session.is_none() {
                return Ok(());
            }
            self.dec_session.as_ref()
        } else {
            if self.enc_session.is_none() {
                return Ok(());
            }
            self.enc_session.as_ref()
        };

        // In a real implementation, this would handle parameter encryption/decryption
        // based on the session encryption scheme. This is a placeholder.

        Ok(())
    }

    /// Get RP hash (response parameter hash)
    fn get_rp_hash(
        &self,
        hash_alg: TPM_ALG_ID,
        resp_buf: &mut TpmBuffer,
        cmd_code: TPM_CC,
        resp_params_pos: usize,
        resp_params_size: usize,
        rp_ready: bool,
    ) -> Result<Vec<u8>, TpmError> {
        let rp_header_size = 8;
        let rp_hash_data_pos = resp_params_pos - rp_header_size;

        if !rp_ready {
            // Create a continuous data area required by rpHash
            let orig_cur_pos = resp_buf.current_pos();
            resp_buf.set_current_pos(rp_hash_data_pos);
            resp_buf.writeInt(TPM_RC::SUCCESS.get_value());
            resp_buf.writeInt(cmd_code.get_value());
            resp_buf.set_current_pos(orig_cur_pos);
        }

        let data_to_hash = &resp_buf.buffer()
            [rp_hash_data_pos..(rp_hash_data_pos + rp_header_size + resp_params_size)];
        Crypto::hash(hash_alg, data_to_hash)
    }

    /// Process response sessions
    fn process_resp_sessions(
        &mut self,
        resp_buf: &mut TpmBuffer,
        cmd_code: TPM_CC,
        resp_params_pos: usize,
        resp_params_size: usize,
    ) -> Result<bool, TpmError> {
        let mut rp_ready = false;
        resp_buf.set_current_pos(resp_params_pos + resp_params_size);

        if let Some(ref mut sessions) = self.sessions {
            for (j, session) in sessions.iter_mut().enumerate() {
                let mut auth_response = TPMS_AUTH_RESPONSE::default();
                auth_response.initFromTpm(resp_buf)?;

                if session.is_pwap() {
                    // PWAP sessions should have empty nonce and hmac
                    if !auth_response.nonce.is_empty() || !auth_response.hmac.is_empty() {
                        return Err(TpmError::GenericError(
                            "Bad value in PWAP session response".to_string(),
                        ));
                    }
                    continue;
                }

                // Non-PWAP session handling
                let associated_handle = if j < self.in_handles.len() {
                    Some(&self.in_handles[j])
                } else {
                    None
                };

                // Update session data based on what the TPM just told us
                session.sess_out.nonce = auth_response.nonce;
                session.sess_out.sessionAttributes = auth_response.sessionAttributes;

                if session.session_type == TPM_SE::HMAC {
                    // Verify HMAC on responses

                    // TODO: Fix this

                    // let rp_hash = self.get_rp_hash(
                    //     session.get_hash_alg(),
                    //     resp_buf,
                    //     cmd_code,
                    //     resp_params_pos,
                    //     resp_params_size,
                    //     rp_ready
                    // );

                    // rp_ready = true;
                    // let expected_hmac = session.get_auth_hmac(
                    //     rp_hash,
                    //     false,
                    //     &self.nonce_tpm_dec,
                    //     &self.nonce_tpm_enc,
                    //     associated_handle
                    // );

                    // if expected_hmac != auth_response.hmac {
                    //     return Err(TpmError::GenericError("Invalid TPM response HMAC".to_string()));
                    // }
                }
            }
        }

        if resp_buf.size() - resp_buf.current_pos() != 0 {
            return Err(TpmError::GenericError(
                "Invalid response buffer: Data beyond the authorization area".to_string(),
            ));
        }

        Ok(rp_ready)
    }

    /// Update request handles based on command
    fn update_request_handles<T: ReqStructure>(
        &mut self,
        cmd_code: TPM_CC,
        req: &T,
    ) -> Result<(), TpmError> {
        // Reset state
        self.object_in_name.clear();

        // This function handles updates to handles based on specific commands
        match cmd_code {
            TPM_CC::HierarchyChangeAuth => {
                // Store auth value for later use
                // In a real implementation, extract the new auth value from the request
                self.object_in_auth = vec![]; // Extract from req
                Ok(())
            }
            TPM_CC::LoadExternal => {
                // Store the name for later use
                // In a real implementation, calculate the name from the public area
                self.object_in_name = vec![]; // Calculate from req
                Ok(())
            }
            TPM_CC::Load => {
                // Store the name for later use
                // In a real implementation, calculate the name from the public area
                self.object_in_name = vec![]; // Calculate from req
                Ok(())
            }
            TPM_CC::NV_ChangeAuth => {
                // Store auth value for later use
                // In a real implementation, extract the new auth value from the request
                self.object_in_auth = vec![]; // Extract from req
                Ok(())
            }
            TPM_CC::ObjectChangeAuth => {
                // Store auth value for later use
                // In a real implementation, extract the new auth value from the request
                self.object_in_auth = vec![]; // Extract from req
                Ok(())
            }
            TPM_CC::PCR_SetAuthValue => {
                // Store auth value for later use
                // In a real implementation, extract the new auth value from the request
                self.object_in_auth = vec![]; // Extract from req
                Ok(())
            }
            TPM_CC::EvictControl => {
                // Store name and auth value for later use
                if (!self.in_handles.is_empty()
                    && self.in_handles[1].get_type() != TPM_HT::PERSISTENT)
                {
                    let handle = &self.in_handles[1];
                    self.object_in_auth = handle.auth_value.clone();
                    self.object_in_name = handle.get_name()?;
                }
                Ok(())
            }
            TPM_CC::Clear => {
                // Reset admin auth values
                if !self.in_handles.is_empty() {
                    let mut handle = self.in_handles[0].clone();
                    handle.set_auth(&[]);
                }
                Ok(())
            }
            TPM_CC::HashSequenceStart => {
                // Store auth value for later use
                // In a real implementation, extract the auth value from the request
                self.object_in_auth = vec![]; // Extract from req
                Ok(())
            }
            _ => Ok(()),
        }
    }

    /// Complete update of request handles after command success
    fn complete_update_request_handles(&mut self, cmd_code: TPM_CC) -> Result<(), TpmError> {
        match cmd_code {
            TPM_CC::HierarchyChangeAuth => {
                // Update the appropriate hierarchy auth value
                if !self.in_handles.is_empty() {
                    match self.in_handles[0].handle {
                        val if val == TPM_RH::OWNER.get_value() => {
                            self.admin_owner.set_auth(&self.object_in_auth)
                        }
                        val if val == TPM_RH::ENDORSEMENT.get_value() => {
                            self.admin_endorsement.set_auth(&self.object_in_auth)
                        }
                        val if val == TPM_RH::PLATFORM.get_value() => {
                            self.admin_platform.set_auth(&self.object_in_auth)
                        }
                        val if val == TPM_RH::LOCKOUT.get_value() => {
                            self.admin_lockout.set_auth(&self.object_in_auth)
                        }
                        _ => {}
                    }

                    // Update handle auth
                    self.in_handles[0].set_auth(&self.object_in_auth);
                }
                Ok(())
            }
            TPM_CC::NV_ChangeAuth => {
                if !self.in_handles.is_empty() {
                    self.in_handles[0].set_auth(&self.object_in_auth);
                }
                Ok(())
            }
            TPM_CC::PCR_SetAuthValue => {
                if !self.in_handles.is_empty() {
                    self.in_handles[0].set_auth(&self.object_in_auth);
                }
                Ok(())
            }
            TPM_CC::EvictControl => {
                // Update handle auth and name
                if self.in_handles.len() >= 2 && self.in_handles[1].get_type() != TPM_HT::PERSISTENT
                {
                    self.in_handles[1].set_auth(&self.object_in_auth);
                    self.in_handles[1].set_name(&self.object_in_name.clone());
                }
                Ok(())
            }
            TPM_CC::Clear => {
                // Reset all hierarchy auth values
                self.admin_lockout.set_auth(&[]);
                self.admin_owner.set_auth(&[]);
                self.admin_endorsement.set_auth(&[]);
                Ok(())
            }
            _ => Ok(()),
        }
    }

    /// Update response handle with name and auth value
    fn update_resp_handle<T: RespStructure>(
        &mut self,
        cmd_code: TPM_CC,
        resp: &mut T,
    ) -> Result<(), TpmError> {
        match cmd_code {
            TPM_CC::Load => {
                // In a real implementation, set the name from the response
                // resp.handle.set_name(resp.name);
                Ok(())
            }
            TPM_CC::CreatePrimary => {
                // In a real implementation, set the name from the response
                // resp.handle.set_name(resp.name);
                Ok(())
            }
            TPM_CC::LoadExternal => {
                // In a real implementation, set the name from the response
                // resp.handle.set_name(resp.name);
                Ok(())
            }
            TPM_CC::HashSequenceStart => {
                // In a real implementation, set the auth value on the returned handle
                // resp.handle.set_auth(self.object_in_auth.clone());
                Ok(())
            }
            _ => Ok(()),
        }
    }
}

/// Factory function to create a new TPM implementation based on the available platform
pub fn create_tpm() -> Tpm2 {
    #[cfg(target_os = "windows")]
    {
        use crate::device::TpmTbsDevice;
        Tpm2::new(Box::new(TpmTbsDevice::new()))
    }
    #[cfg(not(target_os = "windows"))]
    {
        use crate::device::{TpmTbsDevice, TpmTcpDevice};

        // Try to create a TBS device first (for Linux/Unix), falling back to TCP simulator
        let mut tbs_device = TpmTbsDevice::new();
        match tbs_device.connect() {
            Ok(_) => Tpm2::new(tbs_device),
            Err(_) => {
                // Fall back to TCP simulator
                let tcp_device = TpmTcpDevice::new("127.0.0.1".to_string(), 2321);
                Tpm2::new(Box::new(tcp_device))
            }
        }
    }
}

/// Factory function to create a TPM implementation with a custom device
pub fn create_tpm_with_device(device: Box<dyn TpmDevice>) -> Tpm2 {
    Tpm2::new(device)
}
