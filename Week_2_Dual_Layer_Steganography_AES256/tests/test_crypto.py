"""
Unit tests for authenticated AES-256-GCM encryption and decryption.
"""

from __future__ import annotations

import sys
from pathlib import Path

# Support running pytest from parent root or subproject directory
_project_root = Path(__file__).resolve().parent.parent
_parent_root = _project_root.parent
for _p in [str(_parent_root), str(_project_root)]:
    if _p not in sys.path:
        sys.path.insert(0, _p)

try:
    from Week_2_Dual_Layer_Steganography_AES256.src.crypto import (
        encrypt_payload,
        decrypt_payload,
        derive_key,
        CryptoError,
        AuthenticationFailedError,
        InvalidKeyError,
        SALT_SIZE_BYTES,
        NONCE_SIZE_BYTES,
        TAG_SIZE_BYTES,
    )
except ImportError:
    from src.crypto import (
        encrypt_payload,
        decrypt_payload,
        derive_key,
        CryptoError,
        AuthenticationFailedError,
        InvalidKeyError,
        SALT_SIZE_BYTES,
        NONCE_SIZE_BYTES,
        TAG_SIZE_BYTES,
    )

import pytest


class TestCryptoEngine:
    """Test cryptographic guarantees of AES-256-GCM."""

    def test_encrypt_decrypt_roundtrip(self) -> None:
        message = "CONFIDENTIAL: Patient biopsy results are negative for malignancy."
        password = "MedicalDoctorSecretPassword123!"

        ciphertext = encrypt_payload(message, password)
        assert isinstance(ciphertext, bytes)
        # Length check: salt(16) + nonce(12) + len(msg) + tag(16)
        expected_min_len = SALT_SIZE_BYTES + NONCE_SIZE_BYTES + len(message) + TAG_SIZE_BYTES
        assert len(ciphertext) == expected_min_len

        decrypted = decrypt_payload(ciphertext, password)
        assert decrypted.decode("utf-8") == message

    def test_unique_nonce_and_salt_per_call(self) -> None:
        message = "Identical message content"
        password = "StaticPassword!"

        ct1 = encrypt_payload(message, password)
        ct2 = encrypt_payload(message, password)

        # Ciphertexts must differ due to random salt & nonce
        assert ct1 != ct2
        # Salts must differ
        assert ct1[:SALT_SIZE_BYTES] != ct2[:SALT_SIZE_BYTES]

    def test_wrong_password_fails_authentication(self) -> None:
        message = "Secret medical history"
        ct = encrypt_payload(message, "CorrectPassword!")

        with pytest.raises(AuthenticationFailedError):
            decrypt_payload(ct, "WrongPassword!")

    def test_tampered_ciphertext_fails_authentication(self) -> None:
        message = "Integrity critical prescription: 5mg Warfarin"
        ct = bytearray(encrypt_payload(message, "Passphrase!"))

        # Corrupt a single bit in the ciphertext portion
        ct[-1] ^= 0x01

        with pytest.raises(AuthenticationFailedError):
            decrypt_payload(bytes(ct), "Passphrase!")

    def test_tampered_nonce_fails_authentication(self) -> None:
        message = "Prescription order"
        ct = bytearray(encrypt_payload(message, "Passphrase!"))

        # Corrupt a byte in the nonce portion
        ct[SALT_SIZE_BYTES + 2] ^= 0x01

        with pytest.raises(AuthenticationFailedError):
            decrypt_payload(bytes(ct), "Passphrase!")

    def test_empty_or_invalid_inputs(self) -> None:
        with pytest.raises(ValueError):
            encrypt_payload("", "Password123")

        with pytest.raises(InvalidKeyError):
            encrypt_payload("Data", "")

        with pytest.raises(CryptoError):
            decrypt_payload(b"too_short", "Password123")
