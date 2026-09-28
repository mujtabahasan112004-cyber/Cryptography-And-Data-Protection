"""
Week 2: Dual-Layer Steganography with AES-256 Payload Protection for Medical Imaging.
"""

from .crypto import encrypt_payload, decrypt_payload, CryptoError, AuthenticationFailedError
from .stego import DualLayerStego, StegoError, CapacityExceededError
from .image_metrics import compute_image_metrics, ImageQualityMetrics
from .sample_generator import generate_synthetic_mri, generate_synthetic_xray

__all__ = [
    "encrypt_payload",
    "decrypt_payload",
    "CryptoError",
    "AuthenticationFailedError",
    "DualLayerStego",
    "StegoError",
    "CapacityExceededError",
    "compute_image_metrics",
    "ImageQualityMetrics",
    "generate_synthetic_mri",
    "generate_synthetic_xray",
]
