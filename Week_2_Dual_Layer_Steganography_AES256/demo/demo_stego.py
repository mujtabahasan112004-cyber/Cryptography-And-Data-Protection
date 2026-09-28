"""
End-to-End Demonstration Script for Week 2:
Dual-Layer Steganography with AES-256-GCM for Medical Imaging.

Demonstrates:
  INPUT: Synthetic Medical Scan (MRI phantom) + Confidential Patient Record
  PROCESSING: PBKDF2 Key Derivation + AES-256-GCM Encryption
  SECURITY MECHANISM:
    - Layer 1: Spatial Coordinate Permutation
    - Layer 2: LSB Channel Modulation
  OUTPUT: High-Fidelity Stego PNG
  VALIDATION:
    - PSNR & MSE Analysis
    - Successful Plaintext Recovery
    - Wrong Password Rejection
    - Tamper Detection via GCM Authentication Tag
"""

from __future__ import annotations

import sys
from pathlib import Path

# Add project root to sys.path
sys.path.insert(0, str(Path(__file__).parent.parent))

from src.crypto import encrypt_payload, decrypt_payload, AuthenticationFailedError
from src.stego import DualLayerStego, StegoError
from src.image_metrics import compute_image_metrics
from src.sample_generator import generate_synthetic_mri


def run_demonstration() -> None:
    print("\n" + "=" * 75)
    print("   WEEK 2 PROJECT DEMONSTRATION: DUAL-LAYER MEDICAL STEGANOGRAPHY")
    print("=" * 75)

    base_dir = Path(__file__).parent.parent
    sample_img_path = base_dir / "sample_data" / "input.png"
    stego_img_path = base_dir / "output" / "stego_demo.png"
    sample_img_path.parent.mkdir(parents=True, exist_ok=True)
    stego_img_path.parent.mkdir(parents=True, exist_ok=True)

    print("\n[STEP 1] SYNTHETIC MEDICAL IMAGE ACQUISITION")
    if not sample_img_path.exists():
        print("  * Generating 512x512 synthetic Brain MRI phantom (zero HIPAA exposure)...")
        generate_synthetic_mri(512, 512, sample_img_path)
    print(f"  [OK] Cover Medical Image Ready: {sample_img_path}")

    # Confidential clinical report
    confidential_report = (
        "--- CONFIDENTIAL MEDICAL REPORT ---\n"
        "PATIENT ID: MED-2026-99214\n"
        "SCAN TYPE: Brain MRI Axial T2\n"
        "FINDING: Mild microvascular ischemic changes in periventricular white matter.\n"
        "No acute intracranial hemorrhage or mass effect identified.\n"
        "RECOMMENDATION: Routine follow-up in 12 months.\n"
        "SIGNING RADIOLOGIST: Dr. Eleanor Vance, MD (Badge #48291)\n"
        "TIMESTAMP: 2026-09-28T09:40:00Z"
    )
    secret_passphrase = "UltraSecureMedicalPassphrase2026!"

    print("\n[STEP 2] CONFIDENTIAL PAYLOAD DEFINITION")
    print(f"  * Plaintext Message Size: {len(confidential_report)} characters")
    print("  * Preview:\n" + "\n".join("    " + line for line in confidential_report.splitlines()[:3]))
    print("    ...")

    print("\n[STEP 3] AES-256-GCM AUTHENTICATED ENCRYPTION")
    print(f"  * Deriving 256-bit AES key via PBKDF2-HMAC-SHA256 (600,000 rounds)...")
    encrypted_payload = encrypt_payload(confidential_report, secret_passphrase)
    print(f"  * Generated Salt (16B), Nonce (12B), GCM Tag (16B)")
    print(f"  * Total Encrypted Payload: {len(encrypted_payload)} bytes")
    print(f"  * Ciphertext Preview (Hex): {encrypted_payload[:24].hex()}...")

    print("\n[STEP 4] DUAL-LAYER STEGANOGRAPHIC EMBEDDING")
    print("  * Layer 1: Deterministic spatial permutation scattering bits across 512x512 array.")
    print("  * Layer 2: Least Significant Bit (LSB) channel modulation.")
    stego_image = DualLayerStego.embed_payload(sample_img_path, encrypted_payload, stego_key=secret_passphrase)
    stego_image.save(stego_img_path, format="PNG")
    print(f"  [OK] Stego Medical Image Losslessly Saved: {stego_img_path}")

    print("\n[STEP 5] IMAGE QUALITY & RADIOLOGICAL FIDELITY ASSESSMENT")
    metrics = compute_image_metrics(sample_img_path, stego_img_path)
    print(f"  * PSNR (Peak Signal-to-Noise Ratio) : {metrics.psnr:.2f} dB")
    print(f"  * MSE (Mean Squared Error)           : {metrics.mse:.6f}")
    print(f"  * Modified Pixels                    : {metrics.modified_pixels_count:,} / {metrics.total_pixels_count:,} ({metrics.modified_percentage:.3f}%)")
    print(f"  * Clinical Distortion Assessment     : {metrics.fidelity_assessment}")
    assert metrics.psnr > 50.0, "PSNR must exceed 50 dB for diagnostic medical quality."

    print("\n[STEP 6] EXTRACTION & RECOVERY")
    print("  * Extracting steganographic bitstream from stego image...")
    recovered_payload = DualLayerStego.extract_payload(stego_img_path, stego_key=secret_passphrase)
    print(f"  * Recovered {len(recovered_payload)} encrypted bytes")
    print("  * Verifying AES-GCM authentication tag and decrypting...")
    recovered_text = decrypt_payload(recovered_payload, secret_passphrase).decode("utf-8")
    print("  [SUCCESS] Authenticated Decryption Succeeded!")
    assert recovered_text == confidential_report, "Recovered text must match original exactly."
    print("  [VERIFIED] Recovered text matches original plaintext 100%.")

    print("\n[STEP 7] SECURITY VERIFICATION: WRONG PASSWORD DEFENSE")
    try:
        print("  * Attempting decryption with WRONG password: 'WrongPassword123'...")
        decrypt_payload(recovered_payload, "WrongPassword123")
        print("  [-] ERROR: Decryption should have failed!")
    except AuthenticationFailedError:
        print("  [DEFENSE PASS] Correctly rejected! GCM Authentication Tag mismatch.")

    print("\n[STEP 8] SECURITY VERIFICATION: PAYLOAD INTEGRITY / TAMPER DEFENSE")
    try:
        print("  * Tampering with single byte in encrypted payload...")
        tampered = bytearray(recovered_payload)
        tampered[-5] ^= 0x01  # Flip one bit in ciphertext
        decrypt_payload(bytes(tampered), secret_passphrase)
        print("  [-] ERROR: Tampered payload was accepted!")
    except AuthenticationFailedError:
        print("  [DEFENSE PASS] Correctly caught! Bit modification triggered tag validation failure.")

    print("\n" + "=" * 75)
    print("           WEEK 2 DEMONSTRATION COMPLETED SUCCESSFULLY")
    print("=" * 75 + "\n")


if __name__ == "__main__":
    run_demonstration()
