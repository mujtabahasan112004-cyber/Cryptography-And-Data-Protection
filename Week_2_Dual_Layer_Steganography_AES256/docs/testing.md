# Testing Strategy & Test Case Documentation: Dual-Layer Medical Stego

## 1. Overview
The testing framework for Week 2 validates both the cryptographic guarantees (AES-256-GCM authentication, key derivation, tampering resistance) and steganographic guarantees (dual-layer embedding, reversibility, capacity bounding, and image fidelity metrics).

## 2. Test Execution
To run all tests for Week 2:
```powershell
pytest Week_2_Dual_Layer_Steganography_AES256/tests -v
```

## 3. Test Matrix

| Test Identifier | Category | Objective | Pass Criterion |
|---|---|---|---|
| `test_encrypt_decrypt_roundtrip` | Cryptographic | Verify plaintext recovers exactly after AES-256-GCM encrypt/decrypt. | Decrypted bytes == original string. |
| `test_unique_nonce_and_salt_per_call` | Security | Check that identical plaintexts yield different ciphertexts and salts. | $ct_1 \neq ct_2$, $salt_1 \neq salt_2$. |
| `test_wrong_password_fails_authentication` | Security | Attempt decrypting with incorrect passphrase. | Raises `AuthenticationFailedError`. |
| `test_tampered_ciphertext_fails_authentication` | Integrity | Flip a single bit in ciphertext payload. | Raises `AuthenticationFailedError`. |
| `test_tampered_nonce_fails_authentication` | Integrity | Flip a single bit in nonce field. | Raises `AuthenticationFailedError`. |
| `test_empty_or_invalid_inputs` | Input Validation | Pass empty strings, invalid key types, short payloads. | Raises `ValueError` or `CryptoError`. |
| `test_embed_and_extract_roundtrip` | Stego Functional | Embed encrypted payload into synthetic MRI, extract, and decrypt. | Exact plaintext recovered. |
| `test_wrong_stego_key_fails_extraction` | Stego Security | Attempt extraction using wrong spatial permutation stego-key. | Raises `StegoError` (Magic mismatch). |
| `test_high_image_fidelity_psnr` | Quality Assurance | Compute PSNR and MSE on stego image. | PSNR $> 50.0$ dB, Max Delta $\le 1$, MSE $< 0.1$. |
| `test_capacity_exceeded_raises_error` | Bounding | Attempt embedding large payload into tiny 8x8 image. | Raises `CapacityExceededError`. |
| `test_capacity_info_reporting` | Metadata | Query image dimensions and maximum payload byte capacity. | Matches calculated values. |
| `test_nonexistent_image_raises_error` | Error Handling | Pass invalid or non-existent file path to embed/extract. | Raises `InvalidImageError`. |
| `test_synthetic_xray_generator` | Phantom Gen | Generate synthetic chest X-ray image. | Size and mode match expected dimensions. |
