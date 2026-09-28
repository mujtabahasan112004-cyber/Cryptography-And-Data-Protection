#!/usr/bin/env python3
"""
Command-Line Interface for Week 2:
Dual-Layer Steganography with AES-256 Payload Protection for Medical Imaging.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

# Add project root to sys.path
sys.path.insert(0, str(Path(__file__).parent))

from src.crypto import encrypt_payload, decrypt_payload, AuthenticationFailedError, CryptoError
from src.stego import DualLayerStego, StegoError, CapacityExceededError
from src.image_metrics import compute_image_metrics
from src.sample_generator import generate_synthetic_mri, generate_synthetic_xray


def handle_encode(args: argparse.Namespace) -> None:
    # 1. Obtain message text
    if args.message:
        message_text = args.message
    elif args.message_file:
        p = Path(args.message_file)
        if not p.is_file():
            print(f"[-] Error: Message file not found: {p}", file=sys.stderr)
            sys.exit(1)
        message_text = p.read_text(encoding="utf-8")
    else:
        print("[-] Error: Either --message or --message-file is required for encode.", file=sys.stderr)
        sys.exit(1)

    password = args.password
    if not password:
        password = input("Enter encryption passphrase: ").strip()

    stego_key = args.stego_key or password

    print("=" * 65)
    print("      DUAL-LAYER MEDICAL STEGANOGRAPHY: ENCODE PIPELINE")
    print("=" * 65)
    print(f"Input Cover Image : {args.image}")
    print(f"Message Length     : {len(message_text)} characters ({len(message_text.encode('utf-8'))} bytes)")
    print(f"Output Stego Image : {args.output}")

    # Check capacity
    cap = DualLayerStego.get_capacity_info(args.image)
    print(f"Cover Capacity     : {cap['max_payload_bytes']:,} bytes available ({cap['width']}x{cap['height']} {cap['mode']})")

    # Step 1: AES-256-GCM authenticated encryption
    print("\n[STEP 1] Performing AES-256-GCM Authenticated Encryption...")
    encrypted_payload = encrypt_payload(message_text, password)
    print(f"  * Generated 128-bit random salt & 96-bit random nonce")
    print(f"  * PBKDF2-HMAC-SHA256 derived 256-bit key (600,000 rounds)")
    print(f"  * Encrypted ciphertext + 128-bit GCM tag: {len(encrypted_payload)} bytes total")

    # Step 2: Dual-Layer Steganography Embedding
    print("\n[STEP 2] Executing Dual-Layer Steganographic Embedding...")
    print("  * Layer 1: Pseudo-random spatial permutation (scattering across coordinates)")
    print("  * Layer 2: Least Significant Bit (LSB) channel modulation")
    stego_img = DualLayerStego.embed_payload(args.image, encrypted_payload, stego_key=stego_key)

    out_p = Path(args.output)
    out_p.parent.mkdir(parents=True, exist_ok=True)
    stego_img.save(out_p, format="PNG")
    print(f"\n[OK] Stego image successfully written losslessly to: {out_p}")

    # Step 3: Compute Quality Metrics
    print("\n[STEP 3] Calculating Image Quality & Distortion Metrics...")
    metrics = compute_image_metrics(args.image, out_p)
    print(f"  * PSNR (Peak Signal-to-Noise Ratio) : {metrics.psnr:.2f} dB")
    print(f"  * MSE (Mean Squared Error)           : {metrics.mse:.6f}")
    print(f"  * Modified Pixels                    : {metrics.modified_pixels_count:,} / {metrics.total_pixels_count:,} ({metrics.modified_percentage:.3f}%)")
    print(f"  * Clinical Assessment                : {metrics.fidelity_assessment}")
    print("=" * 65)


def handle_decode(args: argparse.Namespace) -> None:
    password = args.password
    if not password:
        password = input("Enter decryption passphrase: ").strip()

    stego_key = args.stego_key or password

    print("=" * 65)
    print("      DUAL-LAYER MEDICAL STEGANOGRAPHY: DECODE PIPELINE")
    print("=" * 65)
    print(f"Stego Image Source : {args.image}")

    try:
        # Step 1: Extract Steganographic Payload
        print("\n[STEP 1] Extracting Steganographic Bitstream...")
        print("  * Reversing Layer 2 (LSB unmasking)")
        print("  * Reversing Layer 1 (Deterministic spatial unpermuting)")
        encrypted_payload = DualLayerStego.extract_payload(args.image, stego_key=stego_key)
        print(f"  * Successfully recovered {len(encrypted_payload)} encrypted payload bytes")

        # Step 2: AES-256-GCM Decryption & Authentication
        print("\n[STEP 2] Verifying AES-256-GCM Authentication & Decrypting...")
        plaintext_bytes = decrypt_payload(encrypted_payload, password)
        plaintext = plaintext_bytes.decode("utf-8")
        print("  [SUCCESS] GCM Authentication Tag Verified! Integrity Guaranteed.")
        print("\n" + "-" * 65)
        print("RECOVERED PLAINTEXT MESSAGE:")
        print(plaintext)
        print("-" * 65)

        if args.output:
            out_p = Path(args.output)
            out_p.parent.mkdir(parents=True, exist_ok=True)
            out_p.write_text(plaintext, encoding="utf-8")
            print(f"[OK] Plaintext message saved to: {out_p}")

    except AuthenticationFailedError as e:
        print(f"\n[-] SECURITY ALERT: {e}", file=sys.stderr)
        print("[-] Decryption aborted: GCM Tag mismatch. Key is invalid or data was tampered!", file=sys.stderr)
        sys.exit(2)
    except StegoError as e:
        print(f"\n[-] STEGANOGRAPHY ERROR: {e}", file=sys.stderr)
        sys.exit(3)
    except Exception as e:
        print(f"\n[-] UNEXPECTED ERROR: {e}", file=sys.stderr)
        sys.exit(1)


def handle_metrics(args: argparse.Namespace) -> None:
    print("=" * 65)
    print("        IMAGE QUALITY AND FIDELITY COMPARISON")
    print("=" * 65)
    metrics = compute_image_metrics(args.original, args.stego)
    print(f"Original Cover Image : {args.original}")
    print(f"Stego Image Target   : {args.stego}")
    print("-" * 65)
    print(f"PSNR (Peak Signal-to-Noise Ratio) : {metrics.psnr:.2f} dB")
    print(f"MSE (Mean Squared Error)           : {metrics.mse:.6f}")
    print(f"MAE (Mean Absolute Error)          : {metrics.mae:.6f}")
    print(f"Max Pixel Delta                    : {metrics.max_delta} (Scale 0-255)")
    print(f"Modified Pixels Count              : {metrics.modified_pixels_count:,} / {metrics.total_pixels_count:,}")
    print(f"Modified Percentage                : {metrics.modified_percentage:.4f}%")
    print(f"Fidelity Assessment                : {metrics.fidelity_assessment}")
    print("=" * 65)


def handle_sample(args: argparse.Namespace) -> None:
    out_p = Path(args.output)
    if args.type == "mri":
        generate_synthetic_mri(512, 512, out_p)
        print(f"[OK] Generated synthetic Brain MRI phantom at: {out_p}")
    else:
        generate_synthetic_xray(512, 512, out_p)
        print(f"[OK] Generated synthetic Chest X-Ray phantom at: {out_p}")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Dual-Layer Steganography with AES-256-GCM Payload Protection for Medical Imaging",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    subparsers = parser.add_subparsers(dest="command", help="Available subcommands")

    # Encode
    p_encode = subparsers.add_parser("encode", help="Encrypt and hide message inside cover image")
    p_encode.add_argument("--image", required=True, help="Path to cover image (PNG)")
    p_encode.add_argument("--message", help="Secret message string")
    p_encode.add_argument("--message-file", help="Path to text file containing secret message")
    p_encode.add_argument("--output", required=True, help="Destination path for stego image (PNG)")
    p_encode.add_argument("--password", required=True, help="Encryption passphrase")
    p_encode.add_argument("--stego-key", help="Optional stego spatial permutation key (defaults to password)")

    # Decode
    p_decode = subparsers.add_parser("decode", help="Extract and decrypt hidden message from stego image")
    p_decode.add_argument("--image", required=True, help="Path to stego image")
    p_decode.add_argument("--password", required=True, help="Decryption passphrase")
    p_decode.add_argument("--stego-key", help="Optional stego spatial permutation key (defaults to password)")
    p_decode.add_argument("--output", help="Optional output text file for recovered message")

    # Metrics
    p_metrics = subparsers.add_parser("metrics", help="Compute PSNR, MSE, and pixel distortion metrics")
    p_metrics.add_argument("--original", required=True, help="Original cover image")
    p_metrics.add_argument("--stego", required=True, help="Stego image")

    # Generate Sample
    p_sample = subparsers.add_parser("generate-sample", help="Generate synthetic HIPAA-safe medical phantom image")
    p_sample.add_argument("--type", choices=["mri", "xray"], default="mri", help="Phantom type")
    p_sample.add_argument("--output", default="sample_data/synthetic_scan.png", help="Output path")

    # Demo
    subparsers.add_parser("demo", help="Run automated end-to-end demonstration")

    args = parser.parse_args()

    if args.command == "encode":
        handle_encode(args)
    elif args.command == "decode":
        handle_decode(args)
    elif args.command == "metrics":
        handle_metrics(args)
    elif args.command == "generate-sample":
        handle_sample(args)
    elif args.command == "demo" or len(sys.argv) == 1:
        from demo.demo_stego import run_demonstration
        run_demonstration()
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
