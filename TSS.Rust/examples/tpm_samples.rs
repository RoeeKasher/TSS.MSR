use std::io::{self, Write};
use tss_rust::{
    device::{TpmDevice, TpmTbsDevice}, error::TpmError, tpm2_impl::*, tpm_structure::{TpmEnum}, tpm_types::*, tpm_type_extensions::*
};

lazy_static::lazy_static! {
    pub static ref Aes128Cfb: TPMT_SYM_DEF_OBJECT = TPMT_SYM_DEF_OBJECT::new(TPM_ALG_ID::AES, 128, TPM_ALG_ID::CFB);
}

fn set_color(color: u8) {
    // This function simulates setting text color. In a real application, you can use libraries like `termcolor` or `colored`.
    // This is just a placeholder since color setting is typically platform-dependent (like ANSI codes on Linux/macOS).
    if color == 0 {
        print!("\x1b[0m"); // Reset color (for simplicity, this is just a reset for terminal color)
    } else {
        print!("\x1b[1;32m"); // Green color (for example, setting to green)
    }
}

fn announce(test_name: &str) {
    set_color(1); // Reset color (probably to default)
    println!();
    println!("==============================================================================================================================");
    println!("               {}", test_name);
    println!("==============================================================================================================================");
    println!();
    io::stdout().flush().unwrap(); // Ensure everything is printed out
    set_color(0); // Set color (e.g., green)
}

fn get_capabilities(tpm: &mut Tpm2) -> Result<(), Box<dyn std::error::Error>> {
    let mut start_val = 0;

    announce("************************* Algorithms *************************");

    // For the first example we show how to get a batch (8) properties at a time.
    // For simplicity, subsequent samples just get one at a time: avoiding the
    // nested loop.

    loop {
        let addition_to_start_val: u32;

        let caps = tpm.GetCapability(TPM_CAP::ALGS, start_val, 8)?;
        if let Some(caps) = caps.capabilityData {
            if let TPMU_CAPABILITIES::algorithms(props) = caps {
                for p in props.algProperties.iter() {
                    println!("{}: {}", p.alg, p.algProperties);
                }

                addition_to_start_val = (props.algProperties[props.algProperties.len() - 1]
                    .alg
                    .get_value()
                    + 1)
                .into();
            } else {
                break;
            }
        } else {
            break;
        }

        if (caps.moreData == 0) {
            break;
        }

        start_val += addition_to_start_val;
    }

    start_val = 0;

    let mut supported_commands: Vec<String> = Vec::new();

    loop {
        let caps = tpm.GetCapability(TPM_CAP::COMMANDS, start_val, 32)?;

        if let Some(caps) = caps.capabilityData {
            if let TPMU_CAPABILITIES::command(props) = caps {
                for p in props.commandAttributes.iter() {
                    let command_value = p.get_value() & 0xFFFF;
                    // Decode the packed structure
                    if let Ok(cc) = TPM_CC::try_from(command_value) {
                        supported_commands.push(format!("TPM_CC_{}", cc.to_string()));
                    }
                    // let masked_attr = TPMA_CC::try_from(p.get_value() & 0xFFff0000)?;

                    // println!("Command {}", cc);

                    start_val = command_value;
                }
            } else {
                break;
            }
        } else {
            break;
        }

        if (caps.moreData == 0) {
            break;
        }

        start_val += 1;
    }

    supported_commands.sort();

    let announcement = format!("TPM supports {} commands", supported_commands.len());

    announce(&announcement);
    let column_width = 35;
    let columns = 3;
    let rows = (supported_commands.len() + columns - 1) / columns;

    for row in 0..rows {
        for col in 0..columns {
            let index = row + col * rows;
            if index < supported_commands.len() {
                let cmd = &supported_commands[index];
                print!("{:<width$}", cmd, width = column_width);
            }
        }
        println!(); // Print newline after each row
    }

    Ok(())
}

fn make_storage_primary(tpm: &mut Tpm2) -> Result<TPM_HANDLE, TpmError> {
    let object_attributes = TPMA_OBJECT::decrypt | TPMA_OBJECT::restricted
        | TPMA_OBJECT::fixedParent | TPMA_OBJECT::fixedTPM
        | TPMA_OBJECT::sensitiveDataOrigin | TPMA_OBJECT::userWithAuth;
    
    let parameters = TPMU_PUBLIC_PARMS::rsaDetail(TPMS_RSA_PARMS::new(&Aes128Cfb, &Some(TPMU_ASYM_SCHEME::null(TPMS_NULL_ASYM_SCHEME::default())), 2048, 65537));

    let unique = TPMU_PUBLIC_ID::rsa(TPM2B_PUBLIC_KEY_RSA::default());


    let storage_primary_template = TPMT_PUBLIC::new(TPM_ALG_ID::SHA1,
                    object_attributes,
                    &Vec::new(),           // No policy
                    &Some(parameters),
                    &Some(unique));
    // Create the key
    // if (auth_session)
    //     tpm[*auth_session];

    let create_primary_response = tpm.CreatePrimary(&TPM_HANDLE::new(TPM_RH::OWNER.get_value()),
    &TPMS_SENSITIVE_CREATE::default(),
    &storage_primary_template,
       &Default::default(),
       &Default::default())?;

    Ok(create_primary_response.handle)
}

fn make_child_signing_key(tpm: &mut Tpm2, parent: &TPM_HANDLE, restricted: bool) -> Result<TPM_HANDLE, TpmError>
{
    let restricted_attribute: TPMA_OBJECT = if restricted { TPMA_OBJECT::restricted } else { TPMA_OBJECT(0) };

    let object_attributes = TPMA_OBJECT::sign | TPMA_OBJECT::fixedParent | TPMA_OBJECT::fixedTPM
                | TPMA_OBJECT::sensitiveDataOrigin | TPMA_OBJECT::userWithAuth | restricted_attribute;

    let parameters = TPMU_PUBLIC_PARMS::rsaDetail(TPMS_RSA_PARMS::new(&Default::default(), 
        &Some(TPMU_ASYM_SCHEME::rsassa(TPMS_SIG_SCHEME_RSASSA { hashAlg: TPM_ALG_ID::SHA1 })), 2048, 65537)); // PKCS1.5

    let unique = TPMU_PUBLIC_ID::rsa(TPM2B_PUBLIC_KEY_RSA::default());

    let template = TPMT_PUBLIC::new(TPM_ALG_ID::SHA1, object_attributes, &Default::default(), &Some(parameters), &Some(unique));

    let new_signing_key = tpm.Create(&parent, &Default::default(), &template, &Default::default(), &Default::default())?;

    tpm.Load(&parent, &new_signing_key.outPrivate, &new_signing_key.outPublic)
}

fn make_endorsement_key(tpm: &mut Tpm2) -> Result<TPM_HANDLE, TpmError> {
    let object_attributes = TPMA_OBJECT::decrypt | TPMA_OBJECT::restricted
    | TPMA_OBJECT::fixedParent | TPMA_OBJECT::fixedTPM
    | TPMA_OBJECT::sensitiveDataOrigin | TPMA_OBJECT::userWithAuth;

let parameters = TPMU_PUBLIC_PARMS::rsaDetail(TPMS_RSA_PARMS::new(&Aes128Cfb, &Some(TPMU_ASYM_SCHEME::null(TPMS_NULL_ASYM_SCHEME::default())), 2048, 65537));

let unique = TPMU_PUBLIC_ID::rsa(TPM2B_PUBLIC_KEY_RSA::default());


let template = TPMT_PUBLIC::new(TPM_ALG_ID::SHA1,
                object_attributes,
                &Vec::new(),           // No policy
                &Some(parameters),
                &Some(unique));

                // Create the key
                let create_primary_response = tpm.CreatePrimary(&TPM_HANDLE::new(TPM_RH::ENDORSEMENT.get_value()),
                &TPMS_SENSITIVE_CREATE::default(),
                &template,
                   &Default::default(),
                   &Default::default())?;
            
                Ok(create_primary_response.handle)
}

fn attestation(tpm: &mut Tpm2) -> Result<(), TpmError> {
    announce("Attestation Sample");

    // Attestation is the TPM signing internal data structures. The TPM can perform
    // several-types of attestation: we demonstrate signing PCR, keys, and time.

    // To get attestation information we need a restricted signing key and privacy authorization.
    let primary_key = make_storage_primary(tpm)?;
    let sig_key = make_child_signing_key(tpm, &primary_key, true)?;

    let nonce = vec![2, 6, 1, 1, 9];

    println!(">> PCR Quoting");
    println!("Created and loaded signing key with handle: {:?}", sig_key);
    
    // Set up PCR selection for the quote
    let pcrs_to_quote = TPMS_PCR_SELECTION::get_selection_array(
        TPM_ALG_ID::SHA1, 7 );

    // Do an event to make sure the value is non-zero
    tpm.PCR_Event(&TPM_HANDLE::pcr(7), &vec![1, 2, 3])?;

    // Then read the value so that we can validate the signature later
    let pcr_vals = tpm.PCR_Read(&pcrs_to_quote)?;

    // Do the quote.  Note that we provide a nonce.
    let quote = tpm.Quote(&sig_key, &nonce, &TPMU_SIG_SCHEME::create(TPM_ALG_ID::NULL)?, &pcrs_to_quote)?;
    
    // Need to cast to the proper attestation type to validate
    let attested = quote.quoted.attested;
    
    if let Some(TPMU_ATTEST::quote(quote_attest)) = attested {
        println!("PCR Quote obtained successfully");
        println!("  PCR Quote: {:?}", quote_attest);
        println!("  Nonce: {:?}", quote.quoted.extraData);
    } else {
        println!("Failed to cast to quote attestation");
        return Err(TpmError::InvalidParameter);
    } ;

    let time_nonce: Vec<u8> = vec![1, 6, 8, 2, 1];
    println!(">> Time Quoting, using nonce {:?}", time_nonce);

    let time_quote = tpm.GetTime(&TPM_HANDLE::new(TPM_RH::ENDORSEMENT.get_value()), &sig_key, &time_nonce, &TPMU_SIG_SCHEME::create(TPM_ALG_ID::NULL)?)?;

    if let Some(TPMU_ATTEST::time(time_attest)) = time_quote.timeInfo.attested {
        println!("Time Quote obtained successfully");
        let clock_info = time_attest.time.clockInfo;
        println!("   Firmware Version: {}", time_attest.firmwareVersion);
        println!("   Time: {}", time_attest.time.time);
        println!("   Clock: {}", clock_info.clock);
        println!("   ResetCount: {}", clock_info.resetCount);
        println!("   RestartCount: {}", clock_info.restartCount);
        println!("   Nonce: {:?}", time_quote.timeInfo.extraData);
    } else {
        println!("Failed to cast to quote attestation");
        return Err(TpmError::InvalidParameter);
    } ;

    // Get a key attestation.  For simplicity we have the signingKey self-certify b
    let key_nonce: Vec<u8> = vec![0, 9, 1, 1, 2, 3];
    println!(">> Key Quoting, using nonce {:?}", key_nonce);

    let key_quote = tpm.Certify(&sig_key, &sig_key, &key_nonce, &TPMU_SIG_SCHEME::create(TPM_ALG_ID::NULL)?)?;

    if let Some(TPMU_ATTEST::certify(certify_attest)) = &key_quote.certifyInfo.attested {
        println!("Key certification obtained successfully");
        println!("   Name of certified key: {:?}", certify_attest.name);
        println!("   Qualified name of certified key: {:?}", certify_attest.qualifiedName);
        println!("   nonce: {:?}", &key_quote.certifyInfo.extraData);
        println!("   Signature: {:?}", &key_quote.signature);
    } else {
        println!("Failed to cast to quote attestation");
        return Err(TpmError::InvalidParameter);
    } ;

    let pub_key = tpm.ReadPublic(&sig_key)?;

    if (pub_key.outPublic.validate_certify(&pub_key.outPublic, &key_nonce, &key_quote)?) {
        println!("Key certification signature verification SUCCESSFUL! ✅");
    } else {
        println!("Key certification signature verification FAILED! ❌");
    }

    // // Clean up - flush keys from TPM
    tpm.FlushContext(&sig_key)?;
    println!("Cleaned up keys from TPM");

    Ok(())
}


fn activate_credentials(tpm: &mut Tpm2) -> Result<(), TpmError> {
    announce("Activate Credentials");

    // Make a new EK and get the public key
    let ek_handle = make_endorsement_key(tpm)?;
    let ek_pub_response = tpm.ReadPublic(&ek_handle)?;
    let ek_pub = ek_pub_response.outPublic;

    // Make another key that we will "activate"
    let srk = make_storage_primary(tpm)?;
    let key_to_activate = make_child_signing_key(tpm, &srk, true)?;
    tpm.FlushContext(&srk)?;

    // Make a secret using the TSS.Rust RNG
    let mut secret = Crypto::get_random(20);
    let name_of_key_to_activate = key_to_activate.get_name()?;

    // Use TSS.Rust to get an activation blob
    let cred = ek_pub.create_activation(secret, &name_of_key_to_activate)?;
    let mut recovered_secret = tpm.ActivateCredential(&key_to_activate, &ek_handle, 
                                                     &cred.credential_blob, &cred.secret)?;

    println!("Secret:                         {}", secret);
    println!("Secret recovered from Activate: {}"  recoveredSecret);

    assert!(secret == recoveredSecret, "Secret mismatch when using TSS.Rust to create an activation credential");

    // You can also use the TPM to make the activation credential
    let tpm_activator = tpm.MakeCredential(&ek_handle, secret, &name_of_key_to_activate)?;

    recovered_secret = tpm.ActivateCredential(keyToActivate, ekHandle,
                                             &tpm_activator.credentialBlob, &tpm_activator.secret);

    println!("TPM-created activation blob: Secret recovered from Activate: {}", recoveredSecret);
    
    assert!(secret == recoveredSecret, "Secret mismatch when using the TPM to create an activation credential");

    tpm.FlushContext(ekHandle);
    tpm.FlushContext(keyToActivate);
} // Activate()

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Example usage of the TSS.Rust library
    let mut device = Box::new(TpmTbsDevice::new());
    device.connect()?;
    let mut tpm = create_tpm_with_device(device);

    // Run capabilities test
    get_capabilities(&mut tpm)?;
    
    // Run attestation sample
    attestation(&mut tpm)?;

    announce(
        "************************* 🦀🦀🦀 Generated by Tss.Rust 🦀🦀🦀 *************************",
    );

    Ok(())
}
