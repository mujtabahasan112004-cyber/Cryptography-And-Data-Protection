# Testing Strategy & Test Case Documentation: SPHINCS+ / SLH-DSA

## 1. Overview
The testing framework for Week 3 validates post-quantum keypair generation, pure message signing, signature verification, adversarial tampering detection, armored key serialization, and performance latency benchmarking.

## 2. Test Execution
To run all tests for Week 3:
```powershell
pytest Week_3_SPHINCS_Plus/tests -v
```

## 3. Test Matrix

| Test Identifier | Category | Objective | Pass Criterion |
|---|---|---|---|
| `test_keypair_generation` | Key Management | Verify generated key lengths and structure. | Public key == 32 bytes, Secret key == 64 bytes. |
| `test_valid_signature_verification` | Functional | Verify authentic message and signature. | `verify_signature()` returns `True`, length == 17,088 bytes. |
| `test_modified_message_fails_verification` | Tamper Detection | Attempt verification after modifying message string. | Returns `False` (forgery detected). |
| `test_corrupted_signature_fails_verification` | Integrity | Corrupt bits in both FORS and XMSS portions of signature. | Returns `False` (signature rejected). |
| `test_wrong_public_key_fails` | Authentication | Verify valid signature under a different public key. | Returns `False`. |
| `test_armored_key_export_import` | Format | Convert keys to PEM-style armored text and re-import. | Re-imported bytes equal original keys. |
| `test_file_io_roundtrip` | Disk I/O | Save keys to disk and load them back. | Loaded keys match generated keys. |
| `test_invalid_key_lengths_raise_exception` | Error Handling | Pass malformed key digests to sign and verify. | Raises `SphincsKeyError` on sign; returns `False` on verify. |
| `test_missing_key_file_raises_error` | Error Handling | Attempt loading non-existent key file. | Raises `FileNotFoundError`. |
| `test_metadata_reporting` | Specification | Query algorithm metadata for `slhdsa-sha2-128f`. | Returns valid parameters and quantum threat descriptions. |

## 4. Performance Benchmarks
Benchmarking results on standard modern hardware (Python 3.13 / Windows):
- **Key Generation**: ~20 - 30 ms
- **Signing**: ~250 - 300 ms
- **Verification**: ~15 - 20 ms
- **Public Key Size**: 32 bytes
- **Secret Key Size**: 64 bytes
- **Signature Size**: 17,088 bytes (~16.7 KB)
