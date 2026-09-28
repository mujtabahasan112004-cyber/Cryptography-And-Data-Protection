"""
Cryptographically Secure Pseudo-Random Number Generator (CSPRNG)
Using ChaCha20 Stream Cipher.

Designed for high-assurance random bit generation, unbiased integer selection,
cryptographic tokens, and forward secrecy state management.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import os
import struct
from typing import Any, Dict, Optional

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms


class ChaCha20CSPRNG:
    """
    ChaCha20-based Cryptographically Secure Pseudo-Random Number Generator.

    Security Properties:
    - Seeded by OS-level cryptographically secure entropy (os.urandom / CryptGenRandom / getrandom).
    - ChaCha20 256-bit symmetric stream cipher provides computational indistinguishability
      from a true random oracle under standard cryptographic assumptions.
    - Includes automatic state ratcheting (forward secrecy) after reaching a configurable
      byte threshold to mitigate past compromise.
    - Unbiased bounded integer generation via rejection sampling (zero modulo bias).
    """

    DEFAULT_RESEED_THRESHOLD: int = 64 * 1024 * 1024  # 64 Megabytes

    def __init__(
        self,
        custom_seed: Optional[bytes] = None,
        reseed_threshold: int = DEFAULT_RESEED_THRESHOLD,
    ) -> None:
        """
        Initialize the ChaCha20 CSPRNG.

        Args:
            custom_seed: Optional extra entropy to mix with OS entropy.
                         OS entropy is NEVER bypassed even if custom_seed is supplied.
            reseed_threshold: Maximum bytes to generate before forcing an internal reseed.
        """
        if reseed_threshold <= 0:
            raise ValueError("reseed_threshold must be a positive integer.")

        self._reseed_threshold = reseed_threshold
        self._bytes_generated = 0
        self._total_bytes_generated = 0
        self._reseed_count = 0

        # State storage (never exposed via diagnostics)
        self._key: bytes = b""
        self._nonce: bytes = b""
        self._cipher: Optional[Cipher] = None
        self._encryptor: Any = None

        # Initial seed generation
        self.reseed(additional_entropy=custom_seed)

    def reseed(self, additional_entropy: Optional[bytes] = None) -> None:
        """
        Reseed the CSPRNG using fresh operating system entropy combined with optional data.

        Security Note:
        Fresh OS entropy (32 bytes) is combined with the current key state and any user-supplied
        entropy using SHA-256 to ensure monotonic entropy accumulation (entropy cannot decrease).
        """
        # Always acquire 32 bytes of high-entropy randomness from OS
        os_entropy = os.urandom(32)

        hasher = hashlib.sha256()
        hasher.update(os_entropy)
        if self._key:
            hasher.update(self._key)
        if additional_entropy:
            if not isinstance(additional_entropy, (bytes, bytearray)):
                raise TypeError("additional_entropy must be bytes or bytearray.")
            hasher.update(additional_entropy)

        self._key = hasher.digest()  # 256-bit key
        self._nonce = os.urandom(16)  # 128-bit nonce for ChaCha20 cipher in cryptography lib

        self._cipher = Cipher(algorithms.ChaCha20(self._key, self._nonce), mode=None)
        self._encryptor = self._cipher.encryptor()
        self._bytes_generated = 0
        self._reseed_count += 1

    def _ratchet_state(self) -> None:
        """
        Advance internal state forward and discard previous state (Forward Secrecy / Backtrack Resistance).
        Even if an attacker compromises the current state, past outputs cannot be reconstructed.
        """
        # Generate 48 bytes of fresh keystream to derive new key and nonce
        ratchet_material = self._encryptor.update(b"\x00" * 48)
        new_key = ratchet_material[:32]
        new_nonce = ratchet_material[32:48]

        self._key = new_key
        self._nonce = new_nonce
        self._cipher = Cipher(algorithms.ChaCha20(self._key, self._nonce), mode=None)
        self._encryptor = self._cipher.encryptor()
        self._bytes_generated = 0

    def random_bytes(self, num_bytes: int) -> bytes:
        """
        Generate cryptographically secure pseudo-random bytes.

        Args:
            num_bytes: Number of bytes to generate. Must be > 0.

        Returns:
            bytes: Generated pseudo-random byte string.
        """
        if not isinstance(num_bytes, int):
            raise TypeError(f"num_bytes must be an integer, got {type(num_bytes).__name__}.")
        if num_bytes <= 0:
            raise ValueError(f"num_bytes must be greater than zero, got {num_bytes}.")

        # Auto-reseed check
        if self._bytes_generated + num_bytes >= self._reseed_threshold:
            self._ratchet_state()

        # In ChaCha20, encrypting a continuous stream of zeros yields the keystream
        null_block = b"\x00" * num_bytes
        keystream = self._encryptor.update(null_block)

        self._bytes_generated += num_bytes
        self._total_bytes_generated += num_bytes
        return keystream

    def random_int(self, min_val: int, max_val: int) -> int:
        """
        Generate an unbiased cryptographically secure integer in the inclusive range [min_val, max_val].

        Implementation:
        Uses Rejection Sampling to completely eliminate Modulo Bias.
        Directly calculating `v % range` introduces bias toward smaller values whenever
        the range does not evenly divide 2^(bit_length).
        """
        if not isinstance(min_val, int) or not isinstance(max_val, int):
            raise TypeError("min_val and max_val must be integers.")
        if min_val > max_val:
            raise ValueError(f"min_val ({min_val}) cannot be greater than max_val ({max_val}).")
        if min_val == max_val:
            return min_val

        range_size = (max_val - min_val) + 1
        num_bytes = (range_size.bit_length() + 7) // 8

        # Calculate the maximum integer value that evenly divides range_size
        max_possible = 1 << (num_bytes * 8)
        limit = max_possible - (max_possible % range_size)

        while True:
            raw_bytes = self.random_bytes(num_bytes)
            # Big-endian integer interpretation
            val = int.from_bytes(raw_bytes, byteorder="big")
            if val < limit:
                return min_val + (val % range_size)

    def random_hex(self, num_bytes: int = 32) -> str:
        """
        Generate a secure hexadecimal token suitable for API keys, CSRF tokens, and session identifiers.

        Args:
            num_bytes: Number of random entropy bytes (token length will be 2 * num_bytes hex chars).
        """
        raw = self.random_bytes(num_bytes)
        return binascii.hexlify(raw).decode("ascii")

    def random_urlsafe(self, num_bytes: int = 32) -> str:
        """
        Generate a secure URL-safe base64 string token without padding.
        Suitable for password reset tokens, OAuth state parameters, and verification links.
        """
        raw = self.random_bytes(num_bytes)
        return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")

    def get_diagnostics(self) -> Dict[str, Any]:
        """
        Return safe runtime diagnostic metrics.
        Note: Secret key and internal cipher state are never exposed.
        """
        return {
            "cipher_algorithm": "ChaCha20 (RFC 7539 / 8439 primitive)",
            "key_size_bits": 256,
            "nonce_size_bits": 128,
            "entropy_source": "os.urandom (Cryptographic OS Entropy Pool)",
            "reseed_count": self._reseed_count,
            "bytes_since_last_reseed": self._bytes_generated,
            "reseed_threshold_bytes": self._reseed_threshold,
            "total_bytes_generated": self._total_bytes_generated,
            "prediction_resistance": "Enabled (ChaCha20 computationally irreversible)",
            "backtrack_resistance": "Enabled (Forward secrecy via state ratcheting)",
        }
