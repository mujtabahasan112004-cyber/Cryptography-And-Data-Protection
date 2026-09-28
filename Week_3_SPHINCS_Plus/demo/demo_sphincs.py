"""
End-to-End Demonstration Script for Week 3:
Post-Quantum Stateless Hash-Based Signatures Using SPHINCS+ (SLH-DSA).

Demonstrates:
  INPUT: Digital document / transaction message
  PROCESSING: FORS Few-Time Signatures + Hypertree XMSS / WOTS+ Traversal
  SECURITY MECHANISM: Stateless hash-based cryptography (NIST FIPS 205)
  OUTPUT: 17,088-byte post-quantum digital signature
  VALIDATION:
    - Authentic Signature Verification (PASS)
    - Tampered Message Verification (FAIL - Caught!)
    - Tampered Signature Verification (FAIL - Caught!)
    - Wrong Public Key Verification (FAIL - Caught!)
"""

from __future__ import annotations

import sys
import time
from pathlib import Path

# Add project root to sys.path
sys.path.insert(0, str(Path(__file__).parent.parent))

from src.sphincs_engine import SphincsEngine
from src.metadata import get_algorithm_metadata


def run_demonstration(param_set: str = "slhdsa-sha2-128f") -> None:
    print("\n" + "=" * 75)
    print("      WEEK 3 PROJECT DEMONSTRATION: SPHINCS+ / SLH-DSA SIGNATURES")
    print("=" * 75)

    engine = SphincsEngine(param_set)
    meta = get_algorithm_metadata(param_set)

    print(f"\n[STEP 1] POST-QUANTUM ALGORITHM SELECTION")
    print(f"  * Algorithm Standard : {meta['parameters']['nist_standard']}")
    print(f"  * Security Level     : {meta['parameters']['security_category']}")
    print(f"  * Hash Primitive     : {meta['parameters']['hash_function']}")
    print(f"  * Hypertree Structure: {meta['parameters']['hypertree_layers_d']} layers, total height h={meta['parameters']['hypertree_total_height_h']}")

    print("\n[STEP 2] KEY PAIR GENERATION")
    t0 = time.perf_counter()
    keypair = engine.generate_keypair()
    keygen_ms = (time.perf_counter() - t0) * 1000.0

    print(f"  * Keygen Latency     : {keygen_ms:.2f} ms")
    print(f"  * Public Key Size    : {len(keypair.public_key_bytes)} bytes (Compact!)")
    print(f"  * Secret Key Size    : {len(keypair.secret_key_bytes)} bytes")
    print(f"  * Public Key Hex     : {keypair.public_key_hex[:32]}...")

    print("\n[STEP 3] MESSAGE SIGNING")
    message = (
        "POST-QUANTUM DIGITAL CONTRACT #2026-X99\n"
        "ISSUER: Department of Quantum Security & Cryptography\n"
        "SUBJECT: Unconditional Long-Term Document Integrity\n"
        "CLAUSE: Resistant against Shor's and Grover's Quantum Algorithms."
    )
    print(f"  * Message Content:\n" + "\n".join("    " + l for l in message.splitlines()))

    t0 = time.perf_counter()
    signature = engine.sign_message(message, keypair.secret_key_bytes)
    sign_ms = (time.perf_counter() - t0) * 1000.0

    print(f"  * Signing Latency    : {sign_ms:.2f} ms")
    print(f"  * Signature Size     : {len(signature):,} bytes (~{len(signature) / 1024:.1f} KB)")
    print("  * Note: Signature contains FORS authentication paths + XMSS hypertree proofs.")

    print("\n[STEP 4] AUTHENTIC SIGNATURE VERIFICATION")
    t0 = time.perf_counter()
    is_valid = engine.verify_signature(message, signature, keypair.public_key_bytes)
    verify_ms = (time.perf_counter() - t0) * 1000.0

    print(f"  * Verification Time  : {verify_ms:.2f} ms")
    print(f"  * Verification Status: {'[VALID - SIGNATURE VERIFIED]' if is_valid else '[INVALID]'}")
    assert is_valid is True, "Authentic signature must verify successfully."

    print("\n[STEP 5] TAMPER RESISTANCE: MODIFIED MESSAGE ATTACK")
    tampered_message = message.replace("Unconditional", "Compromised")
    print("  * Attacker alters message: 'Unconditional' -> 'Compromised'")
    is_tampered_valid = engine.verify_signature(tampered_message, signature, keypair.public_key_bytes)
    print(f"  * Verification Status: {'[VALID]' if is_tampered_valid else '[FORGERY DETECTED - REJECTED]'}")
    assert is_tampered_valid is False, "Modified message must fail verification."
    print("  [DEFENSE PASS] Modified message correctly rejected!")

    print("\n[STEP 6] TAMPER RESISTANCE: CORRUPTED SIGNATURE ATTACK")
    print("  * Flipping single bit at byte index 500 in 17,088-byte signature...")
    tampered_sig = bytearray(signature)
    tampered_sig[500] ^= 0x01
    is_corrupted_valid = engine.verify_signature(message, bytes(tampered_sig), keypair.public_key_bytes)
    print(f"  * Verification Status: {'[VALID]' if is_corrupted_valid else '[INVALID SIGNATURE - REJECTED]'}")
    assert is_corrupted_valid is False, "Corrupted signature must fail verification."
    print("  [DEFENSE PASS] Signature tampering correctly rejected!")

    print("\n[STEP 7] WRONG PUBLIC KEY ATTACK")
    print("  * Generating second independent keypair...")
    other_keypair = engine.generate_keypair()
    is_wrong_key_valid = engine.verify_signature(message, signature, other_keypair.public_key_bytes)
    print(f"  * Verification Status: {'[VALID]' if is_wrong_key_valid else '[REJECTED - WRONG KEY]'}")
    assert is_wrong_key_valid is False, "Wrong public key must fail verification."
    print("  [DEFENSE PASS] Signature not accepted under different public key!")

    print("\n" + "=" * 75)
    print("           WEEK 3 DEMONSTRATION COMPLETED SUCCESSFULLY")
    print("=" * 75 + "\n")


if __name__ == "__main__":
    run_demonstration()
