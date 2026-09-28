"""
Post-Quantum Digital Signature Engine Implementing NIST FIPS 205 (SLH-DSA / SPHINCS+).

Provides production-quality, student-friendly interfaces for:
- Post-quantum key generation
- Pure message signing (sign_pure)
- Signature verification (verify_pure)
- Key serialization (armored Base64 and raw binary)
- Performance benchmarking and diagnostic metrics
"""

from __future__ import annotations

import base64
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Optional, Tuple, Union

import slhdsa
from slhdsa.exception import SLHDSAException, SLHDSAKeyException


class SphincsError(Exception):
    """Base exception for SPHINCS+ / SLH-DSA operations."""
    pass


class SphincsKeyError(SphincsError):
    """Raised when key data is invalid or corrupted."""
    pass


class SphincsVerifyError(SphincsError):
    """Raised during signature verification errors."""
    pass


@dataclass
class SphincsKeyPair:
    public_key_bytes: bytes
    secret_key_bytes: bytes
    parameter_set: str

    @property
    def public_key_hex(self) -> str:
        return self.public_key_bytes.hex()

    @property
    def secret_key_hex(self) -> str:
        return self.secret_key_bytes.hex()


@dataclass
class SignatureBenchmarkResult:
    parameter_set: str
    keygen_time_ms: float
    sign_time_ms: float
    verify_time_ms: float
    public_key_size_bytes: int
    secret_key_size_bytes: int
    signature_size_bytes: int
    message_size_bytes: int


class SphincsEngine:
    """
    High-level engine for Post-Quantum Stateless Hash-Based Signatures (SLH-DSA / SPHINCS+).
    """

    PARAM_MAP = {
        "slhdsa-sha2-128f": slhdsa.sha2_128f,
        "slhdsa-shake-128f": slhdsa.shake_128f,
        "slhdsa-sha2-128s": slhdsa.sha2_128s,
    }

    def __init__(self, parameter_set: str = "slhdsa-sha2-128f") -> None:
        if parameter_set not in self.PARAM_MAP:
            valid = list(self.PARAM_MAP.keys())
            raise ValueError(f"Unknown parameter set '{parameter_set}'. Supported: {valid}")

        self.param_name = parameter_set
        self._param = self.PARAM_MAP[parameter_set]

    def generate_keypair(self) -> SphincsKeyPair:
        """
        Generate a fresh post-quantum public and secret key pair.
        """
        kp = slhdsa.KeyPair.gen(self._param)
        return SphincsKeyPair(
            public_key_bytes=kp.pub.digest(),
            secret_key_bytes=kp.sec.digest(),
            parameter_set=self.param_name,
        )

    def sign_message(self, message: Union[str, bytes], secret_key_bytes: bytes) -> bytes:
        """
        Sign a message using the post-quantum secret key.

        Args:
            message: Message bytes or UTF-8 string to sign.
            secret_key_bytes: 64-byte SLH-DSA secret key digest.

        Returns:
            bytes: Post-quantum signature (~17,088 bytes for 128f).
        """
        if isinstance(message, str):
            msg_bytes = message.encode("utf-8")
        elif isinstance(message, (bytes, bytearray)):
            msg_bytes = bytes(message)
        else:
            raise TypeError("Message must be string or bytes.")

        try:
            sec_key = slhdsa.SecretKey.from_digest(secret_key_bytes, self._param)
            signature = sec_key.sign_pure(msg_bytes)
            return signature
        except SLHDSAKeyException as e:
            raise SphincsKeyError(f"Invalid secret key: {e}")
        except Exception as e:
            raise SphincsError(f"Signing failed: {e}")

    def verify_signature(
        self,
        message: Union[str, bytes],
        signature_bytes: bytes,
        public_key_bytes: bytes,
    ) -> bool:
        """
        Verify a post-quantum signature against a message and public key.

        Args:
            message: Message bytes or string originally signed.
            signature_bytes: Digital signature to evaluate.
            public_key_bytes: 32-byte SLH-DSA public key digest.

        Returns:
            bool: True if signature is authentic, False otherwise.
        """
        if isinstance(message, str):
            msg_bytes = message.encode("utf-8")
        elif isinstance(message, (bytes, bytearray)):
            msg_bytes = bytes(message)
        else:
            raise TypeError("Message must be string or bytes.")

        try:
            pub_key = slhdsa.PublicKey.from_digest(public_key_bytes, self._param)
            return bool(pub_key.verify_pure(msg_bytes, signature_bytes))
        except Exception:
            return False

    # -------------------------------------------------------------------------
    # Key & Signature Serialization Utilities
    # -------------------------------------------------------------------------

    @staticmethod
    def export_armored_key(key_bytes: bytes, is_private: bool = False) -> str:
        """Export key in PEM-style ASCII armored format."""
        header = "-----BEGIN SLH-DSA SECRET KEY-----" if is_private else "-----BEGIN SLH-DSA PUBLIC KEY-----"
        footer = "-----END SLH-DSA SECRET KEY-----" if is_private else "-----END SLH-DSA PUBLIC KEY-----"
        b64 = base64.b64encode(key_bytes).decode("ascii")
        return f"{header}\n{b64}\n{footer}\n"

    @staticmethod
    def import_armored_key(armored_text: str) -> bytes:
        """Import key from PEM-style ASCII armored format or raw hex/base64."""
        lines = [line.strip() for line in armored_text.strip().splitlines() if line.strip()]
        body_lines = [l for l in lines if not l.startswith("-----")]
        combined = "".join(body_lines)

        try:
            # Try Base64
            return base64.b64decode(combined)
        except Exception:
            # Try Hex
            try:
                return bytes.fromhex(combined)
            except Exception as e:
                raise SphincsKeyError(f"Could not parse key: {e}")

    def save_keys_to_dir(self, keypair: SphincsKeyPair, output_dir: Union[str, Path], prefix: str = "sphincs") -> Tuple[Path, Path]:
        """Save public and secret keys to files in both armored and raw binary formats."""
        out_d = Path(output_dir)
        out_d.mkdir(parents=True, exist_ok=True)

        pub_path = out_d / f"{prefix}_public.key"
        sec_path = out_d / f"{prefix}_secret.key"

        pub_path.write_text(self.export_armored_key(keypair.public_key_bytes, is_private=False), encoding="utf-8")
        sec_path.write_text(self.export_armored_key(keypair.secret_key_bytes, is_private=True), encoding="utf-8")

        return pub_path, sec_path

    def load_key_from_file(self, path: Union[str, Path]) -> bytes:
        """Load key from either text or binary file."""
        p = Path(path)
        if not p.is_file():
            raise FileNotFoundError(f"Key file not found: {p}")
        raw = p.read_bytes()
        try:
            text = raw.decode("utf-8")
            if "-----BEGIN" in text:
                return self.import_armored_key(text)
        except UnicodeDecodeError:
            pass
        return raw

    def run_benchmark(self, iterations: int = 3, message_size: int = 1024) -> SignatureBenchmarkResult:
        """Run performance benchmark measuring keygen, sign, and verify latencies."""
        msg = b"A" * message_size

        keygen_times = []
        sign_times = []
        verify_times = []

        kp = None
        sig = None

        for _ in range(iterations):
            # 1. Keygen
            t0 = time.perf_counter()
            kp = self.generate_keypair()
            keygen_times.append((time.perf_counter() - t0) * 1000.0)

            # 2. Sign
            t0 = time.perf_counter()
            sig = self.sign_message(msg, kp.secret_key_bytes)
            sign_times.append((time.perf_counter() - t0) * 1000.0)

            # 3. Verify
            t0 = time.perf_counter()
            verified = self.verify_signature(msg, sig, kp.public_key_bytes)
            verify_times.append((time.perf_counter() - t0) * 1000.0)
            assert verified is True

        return SignatureBenchmarkResult(
            parameter_set=self.param_name,
            keygen_time_ms=sum(keygen_times) / len(keygen_times),
            sign_time_ms=sum(sign_times) / len(sign_times),
            verify_time_ms=sum(verify_times) / len(verify_times),
            public_key_size_bytes=len(kp.public_key_bytes),
            secret_key_size_bytes=len(kp.secret_key_bytes),
            signature_size_bytes=len(sig),
            message_size_bytes=message_size,
        )
