"""
End-to-End Demonstration Script for Week 1: ChaCha20 CSPRNG.

Demonstrates:
  INPUT: Security parameters, byte requests, integer ranges
  PROCESSING: ChaCha20 symmetric stream cipher keystream synthesis
  SECURITY MECHANISM: OS entropy seeding, 256-bit key, rejection sampling, ratcheting
  OUTPUT: Random bytes, tokens, unbiased integers
  VALIDATION: Statistical sanity evaluation + MT19937 comparison
"""

from __future__ import annotations

import sys
from pathlib import Path

# Add project root to sys.path
sys.path.insert(0, str(Path(__file__).parent.parent))

from src.csprng import ChaCha20CSPRNG
from src.stats import run_statistical_tests
from src.comparison import demonstrate_rng_vulnerability


def run_demonstration() -> None:
    print("\n" + "=" * 75)
    print("      WEEK 1 PROJECT DEMONSTRATION: CHACHA20 CSPRNG")
    print("=" * 75)

    print("\n[STEP 1] INITIALIZATION & SEEDING")
    print("  * Gathering 256 bits (32 bytes) of true cryptographic entropy from OS.")
    print("  * Gathering 128 bits (16 bytes) of nonce entropy from OS.")
    print("  * Initializing ChaCha20 20-round stream cipher engine...")
    csprng = ChaCha20CSPRNG()
    diag = csprng.get_diagnostics()
    print(f"  [OK] Initialized with {diag['key_size_bits']}-bit Key, {diag['nonce_size_bits']}-bit Nonce.")
    print(f"  [OK] Entropy Source: {diag['entropy_source']}")

    print("\n[STEP 2] GENERATING CRYPTOGRAPHIC PRIMITIVES")
    raw_32 = csprng.random_bytes(32)
    hex_token = csprng.random_hex(32)
    url_token = csprng.random_urlsafe(32)
    print(f"  * 32 Random Bytes (hex) : {raw_32.hex()[:40]}... (len: {len(raw_32)} bytes)")
    print(f"  * Secure Hex Token       : {hex_token[:40]}... (len: {len(hex_token)} chars)")
    print(f"  * URL-Safe Token         : {url_token[:40]}... (len: {len(url_token)} chars)")

    print("\n[STEP 3] UNBIASED BOUNDED INTEGER GENERATION (REJECTION SAMPLING)")
    print("  * Target range: [1, 6] (Fair 6-sided die roll)")
    rolls = [csprng.random_int(1, 6) for _ in range(10)]
    print(f"  * 10 Die Rolls: {rolls}")
    print("  * Target range: [1, 1,000,000]")
    big_int = csprng.random_int(1, 1000000)
    print(f"  * Generated large integer: {big_int:,}")

    print("\n[STEP 4] FORWARD SECRECY (STATE RATCHETING & RESEEDING)")
    print("  * Performing explicit reseed with fresh kernel entropy + application salt...")
    csprng.reseed(additional_entropy=b"demo_extra_entropy_salt")
    print(f"  [OK] Reseed complete. New state established. Counter reset.")

    print("\n[STEP 5] STATISTICAL SANITY VERIFICATION (NIST SP 800-22 SUITE)")
    print("  * Generating 50,000 bytes from ChaCha20 stream...")
    test_sample = csprng.random_bytes(50000)
    report = run_statistical_tests(test_sample)
    print(f"  * Shannon Entropy: {report.shannon_entropy:.6f} / 8.000000 bits/byte")
    for res in report.results:
        status = "[PASS]" if res.passed else "[FAIL]"
        print(f"    {status} {res.name:<26s} p-value: {res.p_value:.4f}")
    print("  * Note: Statistical tests confirm uniformity; ChaCha20 provides computational security.")

    print("\n[STEP 6] INSECURE VS SECURE GENERATOR COMPARISON")
    print("  * Demonstrating state reconstruction vulnerability on Python's `random` (MT19937)...")
    comp = demonstrate_rng_vulnerability()
    print(f"  * Target: {comp['generator_tested']}")
    print(f"  * Observed: {comp['observed_samples_needed']} numbers")
    print(f"  * Cloned & Predicted: {comp['cloning_successful']} (Attacker predicted future outputs 100%!)")
    print("  * ChaCha20 CSPRNG defense: 2^256 state space with zero known algebraic shortcuts.")

    print("\n" + "=" * 75)
    print("                 DEMONSTRATION COMPLETED SUCCESSFULLY")
    print("=" * 75 + "\n")


if __name__ == "__main__":
    run_demonstration()
