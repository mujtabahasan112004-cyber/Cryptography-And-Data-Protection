#!/usr/bin/env python3
"""
Command-Line Interface for Week 3:
Post-Quantum Stateless Hash-Based Digital Signatures Using SPHINCS+ (SLH-DSA).
"""

from __future__ import annotations

import argparse
import sys
import time
from pathlib import Path

# Add project root to sys.path
sys.path.insert(0, str(Path(__file__).parent))

from src.sphincs_engine import SphincsEngine, SphincsKeyPair, SphincsError
from src.metadata import get_algorithm_metadata, SPHINCS_PARAMETER_SETS


def handle_keygen(args: argparse.Namespace) -> None:
    engine = SphincsEngine(args.param)
    print("=" * 70)
    print("    POST-QUANTUM KEY GENERATION: SPHINCS+ / SLH-DSA")
    print("=" * 70)
    print(f"Algorithm / Standard : {args.param} (NIST FIPS 205)")
    print("Generating keypair...")
    t0 = time.perf_counter()
    kp = engine.generate_keypair()
    elapsed = (time.perf_counter() - t0) * 1000.0

    out_dir = Path(args.out_dir)
    pub_p, sec_p = engine.save_keys_to_dir(kp, out_dir, prefix=args.prefix)

    print(f"[OK] Key generation completed in {elapsed:.2f} ms")
    print(f"Public Key  : {pub_p} ({len(kp.public_key_bytes)} bytes)")
    print(f"Secret Key  : {sec_p} ({len(kp.secret_key_bytes)} bytes)")
    print(f"Public Key Hex: {kp.public_key_hex}")
    print("=" * 70)


def handle_sign(args: argparse.Namespace) -> None:
    engine = SphincsEngine(args.param)
    msg_path = Path(args.file)
    key_path = Path(args.key)
    sig_path = Path(args.sig)

    if not msg_path.is_file():
        print(f"[-] Error: Message file does not exist: {msg_path}", file=sys.stderr)
        sys.exit(1)
    if not key_path.is_file():
        print(f"[-] Error: Key file does not exist: {key_path}", file=sys.stderr)
        sys.exit(1)

    message_bytes = msg_path.read_bytes()
    sec_key_bytes = engine.load_key_from_file(key_path)

    print("=" * 70)
    print("       POST-QUANTUM MESSAGE SIGNING: SPHINCS+ / SLH-DSA")
    print("=" * 70)
    print(f"Target Message File : {msg_path} ({len(message_bytes):,} bytes)")
    print(f"Signing Secret Key  : {key_path} ({len(sec_key_bytes)} bytes)")

    t0 = time.perf_counter()
    sig = engine.sign_message(message_bytes, sec_key_bytes)
    elapsed = (time.perf_counter() - t0) * 1000.0

    sig_path.parent.mkdir(parents=True, exist_ok=True)
    sig_path.write_bytes(sig)

    print(f"[OK] Digital Signature Generated in {elapsed:.2f} ms")
    print(f"Signature Destination: {sig_path} ({len(sig):,} bytes)")
    print(f"Signature Size Ratio : ~{len(sig) / 1024:.1f} KB (Stateless Hypertree Proof)")
    print("=" * 70)


def handle_verify(args: argparse.Namespace) -> None:
    engine = SphincsEngine(args.param)
    msg_path = Path(args.file)
    key_path = Path(args.key)
    sig_path = Path(args.sig)

    if not msg_path.is_file():
        print(f"[-] Error: Message file does not exist: {msg_path}", file=sys.stderr)
        sys.exit(1)
    if not key_path.is_file():
        print(f"[-] Error: Key file does not exist: {key_path}", file=sys.stderr)
        sys.exit(1)
    if not sig_path.is_file():
        print(f"[-] Error: Signature file does not exist: {sig_path}", file=sys.stderr)
        sys.exit(1)

    message_bytes = msg_path.read_bytes()
    pub_key_bytes = engine.load_key_from_file(key_path)
    sig_bytes = sig_path.read_bytes()

    print("=" * 70)
    print("     POST-QUANTUM SIGNATURE VERIFICATION: SPHINCS+ / SLH-DSA")
    print("=" * 70)
    print(f"Message File : {msg_path} ({len(message_bytes):,} bytes)")
    print(f"Public Key   : {key_path} ({len(pub_key_bytes)} bytes)")
    print(f"Signature    : {sig_path} ({len(sig_bytes):,} bytes)")

    t0 = time.perf_counter()
    is_valid = engine.verify_signature(message_bytes, sig_bytes, pub_key_bytes)
    elapsed = (time.perf_counter() - t0) * 1000.0

    print("-" * 70)
    if is_valid:
        print(f"VERIFICATION RESULT: [VALID SIGNATURE] (Verified in {elapsed:.2f} ms)")
        print("Authenticity and integrity are cryptographically guaranteed against quantum attacks.")
    else:
        print(f"VERIFICATION RESULT: [INVALID SIGNATURE / TAMPER DETECTED]")
        print("The message was altered, the signature was forged, or the wrong public key was used.")
        sys.exit(2)
    print("=" * 70)


def handle_benchmark(args: argparse.Namespace) -> None:
    engine = SphincsEngine(args.param)
    print("=" * 70)
    print("         POST-QUANTUM PERFORMANCE BENCHMARK (SLH-DSA)")
    print("=" * 70)
    print(f"Parameter Set : {args.param}")
    print(f"Iterations    : {args.iterations}")
    print("Running timed tests...")

    res = engine.run_benchmark(iterations=args.iterations)

    print("\n--- LATENCY METRICS ---")
    print(f"  Key Generation Time : {res.keygen_time_ms:8.2f} ms")
    print(f"  Signing Time        : {res.sign_time_ms:8.2f} ms")
    print(f"  Verification Time   : {res.verify_time_ms:8.2f} ms")

    print("\n--- CRYPTOGRAPHIC ARTIFACT SIZES ---")
    print(f"  Public Key Size     : {res.public_key_size_bytes} bytes")
    print(f"  Secret Key Size     : {res.secret_key_size_bytes} bytes")
    print(f"  Signature Size      : {res.signature_size_bytes:,} bytes (~{res.signature_size_bytes / 1024:.1f} KB)")
    print("=" * 70)


def handle_info(args: argparse.Namespace) -> None:
    meta = get_algorithm_metadata(args.param)
    print("=" * 70)
    print("   POST-QUANTUM CRYPTOGRAPHY SPECIFICATION: SPHINCS+ (SLH-DSA)")
    print("=" * 70)
    print("NIST Standard    :", meta["parameters"]["nist_standard"])
    print("Security Category:", meta["parameters"]["security_category"])
    print("Hash Function    :", meta["parameters"]["hash_function"])
    print("Public Key Size  :", meta["parameters"]["public_key_size_bytes"], "bytes")
    print("Secret Key Size  :", meta["parameters"]["secret_key_size_bytes"], "bytes")
    print("Signature Size   :", meta["parameters"]["signature_size_bytes"])
    print("Hypertree Total Height (h):", meta["parameters"]["hypertree_total_height_h"])
    print("Hypertree Layers (d)      :", meta["parameters"]["hypertree_layers_d"])
    print("Subtree Height            :", meta["parameters"]["xmss_subtree_height"])
    print("FORS Trees (k) x Height(b):", f"{meta['parameters']['fors_trees_k']} x {meta['parameters']['fors_height_b']}")

    print("\n[WHY QUANTUM COMPUTERS THREATEN CLASSICAL CRYPTOGRAPHY]")
    print(meta["quantum_threat_breakdown"]["shors_algorithm"])

    print("\n[GROVER'S ALGORITHM & SYMMETRIC/HASH SECURITY]")
    print(meta["quantum_threat_breakdown"]["grovers_algorithm"])

    print("\n[WHY HASH-BASED SIGNATURES ARE CONSERVATIVE & TRUSTED]")
    print(meta["why_hash_based_signatures"])

    print("\n[STATELESS VS STATEFUL SIGNATURES (SPHINCS+ VS XMSS)]")
    print(meta["stateless_vs_stateful"])
    print("=" * 70)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Post-Quantum Stateless Hash-Based Signatures (SPHINCS+ / SLH-DSA NIST FIPS 205)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--param",
        default="slhdsa-sha2-128f",
        choices=["slhdsa-sha2-128f", "slhdsa-shake-128f", "slhdsa-sha2-128s"],
        help="SLH-DSA parameter set (default: slhdsa-sha2-128f)",
    )

    subparsers = parser.add_subparsers(dest="command", help="Available subcommands")

    # Keygen
    p_keygen = subparsers.add_parser("keygen", help="Generate post-quantum keypair")
    p_keygen.add_argument("--out-dir", default="demo", help="Directory to save keys (default: demo)")
    p_keygen.add_argument("--prefix", default="sphincs", help="Filename prefix (default: sphincs)")

    # Sign
    p_sign = subparsers.add_parser("sign", help="Sign message with secret key")
    p_sign.add_argument("--file", required=True, help="Path to message file to sign")
    p_sign.add_argument("--key", required=True, help="Path to secret key file")
    p_sign.add_argument("--sig", required=True, help="Path to output signature file")

    # Verify
    p_verify = subparsers.add_parser("verify", help="Verify signature with public key")
    p_verify.add_argument("--file", required=True, help="Path to message file")
    p_verify.add_argument("--key", required=True, help="Path to public key file")
    p_verify.add_argument("--sig", required=True, help="Path to signature file")

    # Benchmark
    p_bench = subparsers.add_parser("benchmark", help="Measure keygen, sign, verify latency and sizes")
    p_bench.add_argument("--iterations", type=int, default=3, help="Number of benchmark iterations")

    # Info
    subparsers.add_parser("info", help="Display theoretical post-quantum analysis & parameters")

    # Demo
    subparsers.add_parser("demo", help="Run full automated end-to-end post-quantum demonstration")

    args = parser.parse_args()

    if args.command == "keygen":
        handle_keygen(args)
    elif args.command == "sign":
        handle_sign(args)
    elif args.command == "verify":
        handle_verify(args)
    elif args.command == "benchmark":
        handle_benchmark(args)
    elif args.command == "info":
        handle_info(args)
    elif args.command == "demo" or len(sys.argv) == 1:
        from demo.demo_sphincs import run_demonstration
        run_demonstration(param_set=args.param)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
