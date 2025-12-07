# AWS Nitro Attestation Decoder

Decode and verify AWS Nitro Enclave attestation documents.

## Features

- Supports JSON (`{"attestationDocument": "..."}`) or raw base64 formats
- Decodes COSE Sign1 structure and CBOR attestation documents
- Displays module ID, timestamp, PCRs, public key, signature, and user data
- Verifies COSE signature (ES384) and certificate chain
- Clean output with full hex values for signatures and keys

## Quick Start

```bash
uv add cbor2 cryptography
uv run decode_attestation.py
```

## Usage

```bash
# Basic decoding (shows key info with full signature & public key)
uv run decode_attestation.py

# With verification
uv run decode_attestation.py --verify

# Different file
uv run decode_attestation.py --attestation attestation

# Full document structure
uv run decode_attestation.py --full --verify
```

### Options

- `--attestation PATH` - Attestation file (default: `attestation`)
- `--verify` - Verify signature and certificate chain
- `--root-cert PATH` - Root certificate (default: `root.pem`)
- `--full` - Show complete CBOR document structure

## Output Fields

- **Module ID** - Enclave instance identifier
- **Timestamp** - Unix time in milliseconds
- **Digest** - Hash algorithm (SHA384)
- **Signature** - Full 96-byte ES384 signature (hex)
- **Public Key** - Full ECDSA P-384 public key (hex)
- **PCRs** - Platform Configuration Registers (non-zero only)
- **User Data** - Custom application data
- **Certificates** - Enclave cert + CA bundle chain

## Verification

When using `--verify`:
1. Verifies COSE signature (converts IEEE P1363 to DER for ES384)
2. Validates certificate chain: enclave → instance → zonal → regional → root
3. Reports overall attestation status
