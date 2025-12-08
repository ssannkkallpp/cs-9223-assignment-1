# Rekor Log Verification

[![CI](https://github.com/ssannkkallpp/cs-9223-assignment-1/actions/workflows/ci.yml/badge.svg)](https://github.com/ssannkkallpp/cs-9223-assignment-1/actions/workflows/ci.yml)

[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/{owner}/{repo}/badge)](https://scorecard.dev/viewer/?uri=github.com/{owner}/{repo})

A Python tool for verifying entries in the [Sigstore Rekor](https://github.com/sigstore/rekor) transparency log. This project provides functionality to cryptographically verify artifact signatures, inclusion proofs, and consistency proofs against the Rekor public instance.

## Overview

Rekor is an immutable, append-only transparency log designed to store metadata about software artifacts. This verifier allows you to:

- **Retrieve log entries** by index from the Rekor transparency log
- **Verify inclusion proofs** to confirm an entry exists in the log at a specific tree state
- **Verify consistency proofs** to ensure the log satisfies the append-only property
- **Validate artifact signatures** using public key cryptography
- **Fetch the latest checkpoint** from the Rekor server

## Features

- ✅ Merkle tree inclusion proof verification (RFC 6962 compliant)
- ✅ Merkle tree consistency proof verification
- ✅ ECDSA signature verification for artifacts
- ✅ Integration with Sigstore's Rekor public instance
- ✅ Command-line interface with debug mode
- ✅ Comprehensive error handling and input validation

## Installation

### Prerequisites

- Python 3.9
- pip3

### Setup

```bash
pip3 install -r requirements.txt
```

## Usage

### Basic Command

```bash
python3 main.py --help
```

### Get Latest Checkpoint

Retrieve the current state of the Rekor transparency log:

```bash
python3 main.py --checkpoint
```

With debug output (saves checkpoint to `checkpoint.json`):

```bash
python3 main.py --checkpoint --debug
```

### Verify Inclusion Proof

Verify that a specific log entry exists in the transparency log and validate the artifact signature:

```bash
python3 main.py --inclusion <LOG_INDEX> --artifact <ARTIFACT_FILE>
```

Example:

```bash
python3 main.py --inclusion 126574567 --artifact artifact.md
```

### Verify Consistency Proof

Verify that the log has grown consistently between two checkpoints:

```bash
python3 main.py --consistency \
  --tree-id <TREE_ID> \
  --tree-size <PREVIOUS_TREE_SIZE> \
  --root-hash <PREVIOUS_ROOT_HASH>
```

Example:

```bash
python3 main.py --consistency \
  --tree-id "737086e2-081a-4a2a-b8e2-60cff8839c3c" \
  --tree-size 150000000 \
  --root-hash "abcd1234..." \
  --debug
```

## Project Structure

```
.
├── main.py              # Main CLI application with verification logic
├── merkle_proof.py      # Merkle tree proof verification (RFC 6962)
├── util.py              # Cryptographic utilities (key extraction, signature verification)
├── requirements.txt     # Python dependencies
├── artifact.md          # Sample artifact file
├── tests                # Unit tests folder         
└── README.md            
```

## Dependencies

- **sigstore** (3.6.5): Official Sigstore Python client
- **cryptography** (≥41.0.0): Cryptographic operations and certificate handling
- **requests** (≥2.28.0): HTTP client for Rekor API calls

### Debug Mode

Enable verbose output and save intermediate results:

```bash
python3 main.py --checkpoint --debug
```

## Template Source

Template code adapted from:
- [mayank-ramnani/python-rekor-monitor-template](https://github.com/mayank-ramnani/python-rekor-monitor-template)

## Course Information

This project was developed for CS-GY 9223 Assignment 1.

**Repository**: https://github.com/ssannkkallpp/cs-9223-assignment-1

## References

- [Sigstore Rekor](https://github.com/sigstore/rekor)
- [RFC 6962: Certificate Transparency](https://tools.ietf.org/html/rfc6962)
- [Sigstore Documentation](https://docs.sigstore.dev/)

## License

MIT
