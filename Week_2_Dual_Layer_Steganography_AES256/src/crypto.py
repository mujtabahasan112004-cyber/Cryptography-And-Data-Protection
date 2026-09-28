"""
Authenticated AES-256-GCM Cryptographic Engine for Medical Imaging Payload Protection.

Security Highlights:
- AES-256 in Galois/Counter Mode (GCM): Provides both confidentiality and authenticity.
- High-iteration PBKDF2-HMAC-SHA256 (600,000 iterations) key derivation resistant to GPU brute-forcing.
- Unique cryptographically secure 96-bit IV/nonce generated per encryption operation.
- Rejection of tampered data before any plaintext is released.
- Strict prevention of insecure modes (ECB / unauthenticated CBC).
"""

from __future__ import annotations

import os
from typing import Optional, Tuple

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


class CryptoError(Exception):
    """Base exception for cryptographic operations."""
    pass


class AuthenticationFailedError(CryptoError):
    """Raised when GCM authentication tag verification fails (tampering or wrong key)."""
    pass


class InvalidKeyError(CryptoError):
    """Raised when provided passphrase/key is invalid."""
    pass


# Security Parameters
SALT_SIZE_BYTES = 16       # 128-bit PBKDF2 Salt
NONCE_SIZE_BYTES = 12      # 96-bit standard GCM Nonce
TAG_SIZE_BYTES = 16        # 128-bit standard GCM Authentication Tag
KEY_SIZE_BYTES = 32        # 256-bit AES Key
PBKDF2_ITERATIONS = 600_000  # OWASP recommended minimum for PBKDF2-HMAC-SHA256
ASSOCIATED_DATA = b"MED_IMAGE_PAYLOAD_V1"


def derive_key(passphrase: str | bytes, salt: bytes) -> bytes:
    """
    Derive a 256-bit symmetric key from a passphrase and salt using PBKDF2-HMAC-SHA256.
    """
    if isinstance(passphrase, str):
        passphrase_bytes = passphrase.encode("utf-8")
    elif isinstance(passphrase, (bytes, bytearray)):
        passphrase_bytes = bytes(passphrase)
    else:
        raise InvalidKeyError("Passphrase must be a string or bytes.")

    if not passphrase_bytes:
        raise InvalidKeyError("Passphrase cannot be empty.")

    if len(salt) != SALT_SIZE_BYTES:
        raise ValueError(f"Salt must be exactly {SALT_SIZE_BYTES} bytes, got {len(salt)}.")

    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=KEY_SIZE_BYTES,
        salt=salt,
        iterations=PBKDF2_ITERATIONS,
    )
    return kdf.derive(passphrase_bytes)


def encrypt_payload(
    plaintext: str | bytes,
    passphrase: str | bytes,
    associated_data: bytes = ASSOCIATED_DATA,
) -> bytes:
    """
    Encrypt plaintext using AES-256-GCM with PBKDF2 key derivation.

    Returns packed binary payload:
        [16 bytes Salt] + [12 bytes Nonce] + [Ciphertext + 16 bytes Tag]
    """
    if isinstance(plaintext, str):
        plaintext_bytes = plaintext.encode("utf-8")
    elif isinstance(plaintext, (bytes, bytearray)):
        plaintext_bytes = bytes(plaintext)
    else:
        raise TypeError("Plaintext must be str or bytes.")

    if not plaintext_bytes:
        raise ValueError("Plaintext payload cannot be empty.")

    # Generate fresh cryptographically secure random salt and nonce
    salt = os.urandom(SALT_SIZE_BYTES)
    nonce = os.urandom(NONCE_SIZE_BYTES)

    # Derive 256-bit AES key
    key = derive_key(passphrase, salt)

    # AES-256-GCM encryption
    aesgcm = AESGCM(key)
    ciphertext_and_tag = aesgcm.encrypt(nonce, plaintext_bytes, associated_data)

    # Pack into single payload: salt (16) + nonce (12) + ciphertext_and_tag
    packed_payload = salt + nonce + ciphertext_and_tag
    return packed_payload


def decrypt_payload(
    packed_payload: bytes,
    passphrase: str | bytes,
    associated_data: bytes = ASSOCIATED_DATA,
) -> bytes:
    """
    Decrypt and verify an AES-256-GCM packed payload.

    Args:
        packed_payload: [16B Salt] + [12B Nonce] + [Ciphertext + 16B Tag]
        passphrase: User secret passphrase.
        associated_data: Authenticated data bound to the ciphertext.

    Returns:
        bytes: Decrypted plaintext bytes.

    Raises:
        AuthenticationFailedError: If tag verification fails or passphrase is wrong.
        CryptoError: If payload is malformed.
    """
    min_len = SALT_SIZE_BYTES + NONCE_SIZE_BYTES + TAG_SIZE_BYTES + 1
    if len(packed_payload) < min_len:
        raise CryptoError(f"Payload too short ({len(packed_payload)} bytes), minimum valid size is {min_len} bytes.")

    salt = packed_payload[:SALT_SIZE_BYTES]
    nonce = packed_payload[SALT_SIZE_BYTES : SALT_SIZE_BYTES + NONCE_SIZE_BYTES]
    ciphertext_and_tag = packed_payload[SALT_SIZE_BYTES + NONCE_SIZE_BYTES :]

    key = derive_key(passphrase, salt)
    aesgcm = AESGCM(key)

    try:
        # AESGCM decrypt verifies authentication tag before returning any plaintext
        plaintext = aesgcm.decrypt(nonce, ciphertext_and_tag, associated_data)
        return plaintext
    except InvalidTag:
        raise AuthenticationFailedError(
            "Authentication failed! The ciphertext has been modified, corrupted, or an incorrect password was supplied."
        )
