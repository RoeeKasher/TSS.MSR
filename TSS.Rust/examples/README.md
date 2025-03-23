# TSS.Rust Examples

This directory contains example code for using the TSS.Rust library.

## Running the Examples

To run the main samples:

```bash
cargo run --example tpm_samples
```

By default, this will try to connect to a TPM simulator. To use a hardware TPM:

```bash
cargo run --example tpm_samples -- tbs
```

## Available Examples

- `tpm_samples.rs` - A comprehensive set of samples demonstrating various TPM operations
  - Random number generation
  - Hash operations
  - HMAC operations
  - PCR operations
  - Primary key creation
  - Attestation operations
  - Encrypt/Decrypt operations

## Note on Implementation

These samples demonstrate how to use the TSS.Rust library with a TPM. Some functions
are placeholders that would need to be implemented based on your specific TPM setup and
the current state of the TSS.Rust library implementation.
