use tss_rust::{device::{TpmDevice, TpmTbsDevice}, tpm2_impl::*, tpm_structure::TpmEnum, tpm_types::{TPMU_CAPABILITIES, TPM_CAP}};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Example usage of the TSS.Rust library
    let mut device = Box::new(TpmTbsDevice::new());
    device.connect()?;
    let mut tpm = create_tpm_with_device(device);

    let mut start_val = 0;

    // For the first example we show how to get a batch (8) properties at a time.
    // For simplicity, subsequent samples just get one at a time: avoiding the
    // nested loop.
    loop {
        let mut addition_to_start_val: u32 = 0;

        let caps = tpm.GetCapability(TPM_CAP::ALGS, start_val, 8)?;
        if let Some(caps) = caps.capabilityData {
            if let TPMU_CAPABILITIES::algorithms(props) = caps {
                for p in props.algProperties.iter() {
                    println!("{}: {}", p.alg, p.algProperties);
                }

                addition_to_start_val = (props.algProperties[props.algProperties.len() - 1].alg.get_value() + 1).into();
            } else {
                break;
            }
        } else {
            break;
        }
        
        if (caps.moreData != 0) {
            break;
        }

        start_val += addition_to_start_val;
    }

    Ok(())
    // cout << "Commands:" << endl;
    // startVal = 0;

    // while (true) {
    //     auto caps = tpm.GetCapability(TPM_CAP::COMMANDS, startVal, 32);
    //     auto comms = dynamic_cast<TPML_CCA*>(&*caps.capabilityData);

    //     for (auto it = comms->commandAttributes.begin(); it != comms->commandAttributes.end(); it++)
    //     {
    //         // Decode the packed structure
    //         TPM_CC cc = *it & 0xFFFF;
    //         TPMA_CC maskedAttr = *it & 0xFFff0000;

    //         cout << "Command:" << EnumToStr(cc) << ": ";
    //         cout << EnumToStr(maskedAttr) << endl;

    //         commandsImplemented.push_back(cc);
    //         startVal = cc;
    //     }
    //     cout << endl;

    //     if (!caps.moreData)
    //         break;
    //     startVal++;
    // }

    // startVal = 0;
    // cout << "PCRS: " << endl;
    // auto caps2 = tpm.GetCapability(TPM_CAP::PCRS, 0, 1);
    // auto pcrs = dynamic_cast<TPML_PCR_SELECTION*>(&*caps2.capabilityData);

    // for (auto it = pcrs->pcrSelections.begin(); it != pcrs->pcrSelections.end(); it++)
    // {
    //     cout << EnumToStr(it->hash) << "\t";
    //     auto pcrsWithThisHash = it->ToArray();

    //     for (auto p = pcrsWithThisHash.begin(); p != pcrsWithThisHash.end(); p++)
    //         cout << *p << " ";
    //     cout << endl;
    // }
}