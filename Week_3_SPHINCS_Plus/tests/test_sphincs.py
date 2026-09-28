"""
Unit tests for SPHINCS+ / SLH-DSA Post-Quantum Digital Signature Engine.
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
    from Week_3_SPHINCS_Plus.src.sphincs_engine import SphincsEngine, SphincsKeyPair, SphincsKeyError, SphincsError
    from Week_3_SPHINCS_Plus.src.metadata import get_algorithm_metadata, SPHINCS_PARAMETER_SETS
except ImportError:
    from src.sphincs_engine import SphincsEngine, SphincsKeyPair, SphincsKeyError, SphincsError
    from src.metadata import get_algorithm_metadata, SPHINCS_PARAMETER_SETS

import pytest


@pytest.fixture
def sphincs_engine() -> SphincsEngine:
    return SphincsEngine("slhdsa-sha2-128f")


@pytest.fixture
def keypair(sphincs_engine: SphincsEngine) -> SphincsKeyPair:
    return sphincs_engine.generate_keypair()


class TestSphincsEngine:
    """Test post-quantum keygen, signing, verification, and adversarial resistance."""

    def test_keypair_generation(self, keypair: SphincsKeyPair) -> None:
        assert isinstance(keypair.public_key_bytes, bytes)
        assert isinstance(keypair.secret_key_bytes, bytes)
        # NIST Category 1 SHA2-128f sizes:
        assert len(keypair.public_key_bytes) == 32
        assert len(keypair.secret_key_bytes) == 64
        assert len(keypair.public_key_hex) == 64

    def test_valid_signature_verification(self, sphincs_engine: SphincsEngine, keypair: SphincsKeyPair) -> None:
        message = "Secure transaction instruction #10492"
        sig = sphincs_engine.sign_message(message, keypair.secret_key_bytes)

        assert isinstance(sig, bytes)
        # SHA2-128f signature size is exactly 17,088 bytes
        assert len(sig) == 17088

        # Verification must succeed
        assert sphincs_engine.verify_signature(message, sig, keypair.public_key_bytes) is True

    def test_modified_message_fails_verification(self, sphincs_engine: SphincsEngine, keypair: SphincsKeyPair) -> None:
        original = "Transfer $100 to Alice"
        tampered = "Transfer $1,000,000 to Mallory"

        sig = sphincs_engine.sign_message(original, keypair.secret_key_bytes)

        # Verification on tampered message must return False
        assert sphincs_engine.verify_signature(tampered, sig, keypair.public_key_bytes) is False

    def test_corrupted_signature_fails_verification(self, sphincs_engine: SphincsEngine, keypair: SphincsKeyPair) -> None:
        message = "Post-quantum verified manifest"
        sig = bytearray(sphincs_engine.sign_message(message, keypair.secret_key_bytes))

        # Flip bit in FORS signature portion
        sig[100] ^= 0x01
        assert sphincs_engine.verify_signature(message, bytes(sig), keypair.public_key_bytes) is False

        # Flip bit in Hypertree XMSS portion
        sig[10000] ^= 0x01
        assert sphincs_engine.verify_signature(message, bytes(sig), keypair.public_key_bytes) is False

    def test_wrong_public_key_fails(self, sphincs_engine: SphincsEngine, keypair: SphincsKeyPair) -> None:
        message = "Authentic dispatch"
        sig = sphincs_engine.sign_message(message, keypair.secret_key_bytes)

        # Generate second different keypair
        other_kp = sphincs_engine.generate_keypair()
        assert sphincs_engine.verify_signature(message, sig, other_kp.public_key_bytes) is False

    def test_armored_key_export_import(self, sphincs_engine: SphincsEngine, keypair: SphincsKeyPair) -> None:
        # Public key
        armored_pub = sphincs_engine.export_armored_key(keypair.public_key_bytes, is_private=False)
        assert "-----BEGIN SLH-DSA PUBLIC KEY-----" in armored_pub
        imported_pub = sphincs_engine.import_armored_key(armored_pub)
        assert imported_pub == keypair.public_key_bytes

        # Secret key
        armored_sec = sphincs_engine.export_armored_key(keypair.secret_key_bytes, is_private=True)
        assert "-----BEGIN SLH-DSA SECRET KEY-----" in armored_sec
        imported_sec = sphincs_engine.import_armored_key(armored_sec)
        assert imported_sec == keypair.secret_key_bytes

    def test_file_io_roundtrip(self, sphincs_engine: SphincsEngine, keypair: SphincsKeyPair, tmp_path: Path) -> None:
        pub_file, sec_file = sphincs_engine.save_keys_to_dir(keypair, tmp_path, prefix="test_key")
        assert pub_file.is_file()
        assert sec_file.is_file()

        loaded_pub = sphincs_engine.load_key_from_file(pub_file)
        loaded_sec = sphincs_engine.load_key_from_file(sec_file)
        assert loaded_pub == keypair.public_key_bytes
        assert loaded_sec == keypair.secret_key_bytes

    def test_invalid_key_lengths_raise_exception(self, sphincs_engine: SphincsEngine) -> None:
        with pytest.raises(SphincsKeyError):
            sphincs_engine.sign_message("data", b"invalid_secret_key_bytes")

        # Invalid public key during verification returns False
        res = sphincs_engine.verify_signature("data", b"X" * 17088, b"short_key")
        assert res is False

    def test_missing_key_file_raises_error(self, sphincs_engine: SphincsEngine) -> None:
        with pytest.raises(FileNotFoundError):
            sphincs_engine.load_key_from_file("non_existent_key_file_123.key")

    def test_metadata_reporting(self) -> None:
        meta = get_algorithm_metadata("slhdsa-sha2-128f")
        assert meta["parameters"]["public_key_size_bytes"] == 32
        assert meta["parameters"]["secret_key_size_bytes"] == 64
        assert "shors_algorithm" in meta["quantum_threat_breakdown"]
