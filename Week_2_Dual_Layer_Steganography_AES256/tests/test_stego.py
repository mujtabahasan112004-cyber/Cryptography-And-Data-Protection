"""
Unit tests for Dual-Layer Steganography, Image Quality Metrics, and Capacity Constraints.
"""

from __future__ import annotations

import io
import sys
from pathlib import Path

# Support running pytest from parent root or subproject directory
_project_root = Path(__file__).resolve().parent.parent
_parent_root = _project_root.parent
for _p in [str(_parent_root), str(_project_root)]:
    if _p not in sys.path:
        sys.path.insert(0, _p)

try:
    from Week_2_Dual_Layer_Steganography_AES256.src.crypto import encrypt_payload, decrypt_payload, AuthenticationFailedError
    from Week_2_Dual_Layer_Steganography_AES256.src.stego import DualLayerStego, StegoError, CapacityExceededError, InvalidImageError
    from Week_2_Dual_Layer_Steganography_AES256.src.image_metrics import compute_image_metrics
    from Week_2_Dual_Layer_Steganography_AES256.src.sample_generator import generate_synthetic_mri, generate_synthetic_xray
except ImportError:
    from src.crypto import encrypt_payload, decrypt_payload, AuthenticationFailedError
    from src.stego import DualLayerStego, StegoError, CapacityExceededError, InvalidImageError
    from src.image_metrics import compute_image_metrics
    from src.sample_generator import generate_synthetic_mri, generate_synthetic_xray

import numpy as np
import pytest
from PIL import Image


@pytest.fixture
def synthetic_mri_image() -> Image.Image:
    """Fixture providing a fresh synthetic 256x256 Brain MRI image in memory."""
    return generate_synthetic_mri(width=256, height=256)


class TestDualLayerStego:
    """Test embedding, extraction, permutation scattering, and image fidelity."""

    def test_embed_and_extract_roundtrip(self, synthetic_mri_image: Image.Image) -> None:
        message = "PATIENT_RECORD: Heart rate 72 bpm, O2 sat 99%, Normal sinus rhythm."
        password = "StegoDoctorSecret2026!"

        # Encrypt with AES-256-GCM
        encrypted = encrypt_payload(message, password)

        # Embed into synthetic MRI
        stego_img = DualLayerStego.embed_payload(synthetic_mri_image, encrypted, stego_key=password)
        assert isinstance(stego_img, Image.Image)
        assert stego_img.size == synthetic_mri_image.size

        # Extract payload
        extracted_encrypted = DualLayerStego.extract_payload(stego_img, stego_key=password)
        assert extracted_encrypted == encrypted

        # Decrypt payload
        decrypted_text = decrypt_payload(extracted_encrypted, password).decode("utf-8")
        assert decrypted_text == message

    def test_wrong_stego_key_fails_extraction(self, synthetic_mri_image: Image.Image) -> None:
        encrypted = encrypt_payload("Sensitive biopsy data", "CorrectKey")
        stego_img = DualLayerStego.embed_payload(synthetic_mri_image, encrypted, stego_key="CorrectKey")

        # Extracting with wrong stego key searches the wrong pseudo-random permutation slots
        with pytest.raises(StegoError):
            DualLayerStego.extract_payload(stego_img, stego_key="WrongStegoKey")

    def test_high_image_fidelity_psnr(self, synthetic_mri_image: Image.Image) -> None:
        encrypted = encrypt_payload("Routine MRI diagnostic scan: No acute pathology detected.", "TestKey")
        stego_img = DualLayerStego.embed_payload(synthetic_mri_image, encrypted, stego_key="TestKey")

        metrics = compute_image_metrics(synthetic_mri_image, stego_img)
        # PSNR must exceed 50 dB for medical diagnostics
        assert metrics.psnr > 50.0, f"Expected PSNR > 50 dB, got {metrics.psnr} dB"
        assert metrics.max_delta <= 1, "LSB embedding must not alter pixel values by more than 1 intensity level"
        assert metrics.mse < 0.1

    def test_capacity_exceeded_raises_error(self) -> None:
        # Create tiny 8x8 RGB image (8*8*3 = 192 bits = 24 bytes total capacity)
        tiny_img = Image.new("RGB", (8, 8), color="white")
        large_payload = b"X" * 100  # 100 bytes is far larger than 24 bytes

        with pytest.raises(CapacityExceededError):
            DualLayerStego.embed_payload(tiny_img, large_payload)

    def test_capacity_info_reporting(self, synthetic_mri_image: Image.Image) -> None:
        cap = DualLayerStego.get_capacity_info(synthetic_mri_image)
        assert cap["width"] == 256
        assert cap["height"] == 256
        assert cap["channels"] == 3
        # 256 * 256 * 3 = 196,608 bits = 24,576 bytes total slots
        assert cap["total_pixel_slots"] == 196608
        assert cap["max_payload_bytes"] > 24000

    def test_nonexistent_image_raises_error(self) -> None:
        with pytest.raises(InvalidImageError):
            DualLayerStego._load_image("non_existent_image_path_12345.png")

    def test_synthetic_xray_generator(self) -> None:
        xray = generate_synthetic_xray(width=128, height=128)
        assert xray.size == (128, 128)
        assert xray.mode == "RGB"
