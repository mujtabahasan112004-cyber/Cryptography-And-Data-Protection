"""
Unit tests for ChaCha20 Cryptographically Secure Pseudo-Random Number Generator.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

# Support running pytest from parent root or subproject directory
_project_root = Path(__file__).resolve().parent.parent
_parent_root = _project_root.parent
for _p in [str(_parent_root), str(_project_root)]:
    if _p not in sys.path:
        sys.path.insert(0, _p)

try:
    from Week_1_CSPRNG_ChaCha20.src.csprng import ChaCha20CSPRNG
    from Week_1_CSPRNG_ChaCha20.src.stats import (
        compute_shannon_entropy,
        monobit_frequency_test,
        runs_test,
        chi_square_test,
        run_statistical_tests,
    )
    from Week_1_CSPRNG_ChaCha20.src.comparison import clone_mersenne_twister, demonstrate_rng_vulnerability
except ImportError:
    from src.csprng import ChaCha20CSPRNG
    from src.stats import (
        compute_shannon_entropy,
        monobit_frequency_test,
        runs_test,
        chi_square_test,
        run_statistical_tests,
    )
    from src.comparison import clone_mersenne_twister, demonstrate_rng_vulnerability

import pytest


class TestChaCha20CSPRNG:
    """Test core CSPRNG functionality, bounds, formats, and exception handling."""

    def test_output_lengths(self) -> None:
        rng = ChaCha20CSPRNG()
        for length in [1, 16, 32, 64, 256, 1024]:
            output = rng.random_bytes(length)
            assert isinstance(output, bytes)
            assert len(output) == length

    def test_output_uniqueness_across_calls(self) -> None:
        rng = ChaCha20CSPRNG()
        outputs = {rng.random_bytes(32) for _ in range(50)}
        assert len(outputs) == 50, "All 50 32-byte sequences must be unique."

    def test_output_uniqueness_across_instances(self) -> None:
        rng1 = ChaCha20CSPRNG()
        rng2 = ChaCha20CSPRNG()
        out1 = rng1.random_bytes(32)
        out2 = rng2.random_bytes(32)
        assert out1 != out2, "Different CSPRNG instances must produce unique output."

    def test_integer_range_correctness(self) -> None:
        rng = ChaCha20CSPRNG()
        min_v, max_v = 10, 25
        for _ in range(200):
            val = rng.random_int(min_v, max_v)
            assert isinstance(val, int)
            assert min_v <= val <= max_v

    def test_integer_range_boundary_values(self) -> None:
        rng = ChaCha20CSPRNG()
        # Single value range
        assert rng.random_int(42, 42) == 42
        # Negative ranges
        for _ in range(50):
            val = rng.random_int(-100, -50)
            assert -100 <= val <= -50
        # Zero-spanning ranges
        for _ in range(50):
            val = rng.random_int(-10, 10)
            assert -10 <= val <= 10

    def test_integer_distribution_coverage(self) -> None:
        rng = ChaCha20CSPRNG()
        observed = set()
        # Draw 100 samples from [1, 6] (die roll)
        for _ in range(100):
            observed.add(rng.random_int(1, 6))
        assert observed == {1, 2, 3, 4, 5, 6}, "All 6 faces of a die should be observed in 100 rolls."

    def test_random_hex_format(self) -> None:
        rng = ChaCha20CSPRNG()
        for byte_len in [16, 32, 48]:
            tok = rng.random_hex(byte_len)
            assert isinstance(tok, str)
            assert len(tok) == byte_len * 2
            assert re.fullmatch(r"^[0-9a-f]+$", tok) is not None

    def test_random_urlsafe_format(self) -> None:
        rng = ChaCha20CSPRNG()
        for byte_len in [16, 32, 64]:
            tok = rng.random_urlsafe(byte_len)
            assert isinstance(tok, str)
            # URL-safe base64: alphanumeric, '-', '_'
            assert re.fullmatch(r"^[A-Za-z0-9_-]+$", tok) is not None
            # No padding '=' characters
            assert "=" not in tok

    def test_reseeding(self) -> None:
        rng = ChaCha20CSPRNG()
        initial_reseed_count = rng.get_diagnostics()["reseed_count"]
        rng.reseed(additional_entropy=b"test_entropy_string")
        assert rng.get_diagnostics()["reseed_count"] == initial_reseed_count + 1
        # Generator remains functional after reseed
        assert len(rng.random_bytes(32)) == 32

    def test_auto_ratcheting_on_threshold(self) -> None:
        # Create generator with very small reseed threshold (128 bytes)
        rng = ChaCha20CSPRNG(reseed_threshold=128)
        # Generate 100 bytes
        _ = rng.random_bytes(100)
        assert rng.get_diagnostics()["bytes_since_last_reseed"] == 100
        # Next 50 bytes triggers internal ratchet
        out = rng.random_bytes(50)
        assert len(out) == 50
        # After ratchet, counter reset and advanced
        assert rng.get_diagnostics()["bytes_since_last_reseed"] == 50

    def test_invalid_arguments_raise_errors(self) -> None:
        rng = ChaCha20CSPRNG()
        # Invalid byte counts
        with pytest.raises(ValueError):
            rng.random_bytes(0)
        with pytest.raises(ValueError):
            rng.random_bytes(-5)
        with pytest.raises(TypeError):
            rng.random_bytes("32")  # type: ignore

        # Invalid integer ranges
        with pytest.raises(ValueError):
            rng.random_int(100, 50)
        with pytest.raises(TypeError):
            rng.random_int("1", 10)  # type: ignore

        # Invalid reseed threshold
        with pytest.raises(ValueError):
            ChaCha20CSPRNG(reseed_threshold=0)

        # Invalid reseed entropy type
        with pytest.raises(TypeError):
            rng.reseed(additional_entropy=12345)  # type: ignore


class TestStatisticalSanity:
    """Test statistical functions and properties."""

    def test_shannon_entropy_calculation(self) -> None:
        # Uniform 256 bytes (one of each value) -> exactly 8.0 bits/byte
        all_bytes = bytes(range(256))
        assert pytest.approx(compute_shannon_entropy(all_bytes), abs=1e-5) == 8.0

        # Monotonous zeroes -> 0.0 bits/byte
        all_zeros = b"\x00" * 100
        assert compute_shannon_entropy(all_zeros) == 0.0

    def test_csprng_passes_statistical_sanity(self) -> None:
        rng = ChaCha20CSPRNG()
        sample = rng.random_bytes(30000)
        report = run_statistical_tests(sample)
        assert report.sample_size_bytes == 30000
        assert report.shannon_entropy > 7.95
        assert report.all_passed, "ChaCha20 output must pass basic statistical uniformity."


class TestOrdinaryRngVulnerability:
    """Test Mersenne Twister cloning vulnerability demonstration."""

    def test_mersenne_twister_cloning(self) -> None:
        result = demonstrate_rng_vulnerability()
        assert result["cloning_successful"] is True
        assert len(result["actual_future_tokens"]) == 5
        assert result["actual_future_tokens"] == result["predicted_tokens"]
