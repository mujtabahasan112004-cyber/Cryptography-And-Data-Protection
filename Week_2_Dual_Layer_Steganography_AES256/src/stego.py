"""
Dual-Layer Steganography Engine for Medical Imaging.

Architecture:
Layer 1: Cryptographic Spatial Permutation (Randomized Pixel Scattering)
         Spreads payload bits non-contiguously across the image coordinate space
         using a pseudo-random permutation derived from a Stego-Key.
         Neutralizes sequential scanline detection and Chi-Square steganalysis.
Layer 2: LSB Channel Embedding (Least Significant Bit Modulation)
         Modulates the lowest bit plane of selected color/grayscale channels
         preserving visual imperceptibility and radiological diagnostic quality.

Header Format (embedded within permuted slots):
[8 Bytes Magic: b"MEDSTEG1"] + [4 Bytes Big-Endian Length] + [N Bytes Encrypted Payload]
"""

from __future__ import annotations

import hashlib
import io
import struct
from pathlib import Path
from typing import List, Optional, Tuple, Union

import numpy as np
from PIL import Image


class StegoError(Exception):
    """Base exception for steganography errors."""
    pass


class CapacityExceededError(StegoError):
    """Raised when payload exceeds available image capacity."""
    pass


class InvalidImageError(StegoError):
    """Raised when image format or data is invalid."""
    pass


MAGIC_HEADER = b"MEDSTEG1"
HEADER_SIZE_BYTES = len(MAGIC_HEADER) + 4  # 8 bytes magic + 4 bytes length = 12 bytes (96 bits)


def _derive_permutation(total_slots: int, stego_key: str | bytes) -> np.ndarray:
    """
    Generate a deterministic pseudo-random permutation of pixel slot indices [0 .. total_slots - 1]
    using a seed derived via SHA-256 from the stego_key.

    Ensures that bits are uniformly scattered across the spatial geometry of the image.
    """
    if isinstance(stego_key, str):
        key_bytes = stego_key.encode("utf-8")
    else:
        key_bytes = bytes(stego_key)

    # Derive 64-bit integer seed from SHA-256 digest
    digest = hashlib.sha256(b"PERM_SALT_" + key_bytes).digest()
    seed = struct.unpack(">Q", digest[:8])[0]

    # NumPy Philox/PCG generator with deterministic seed
    rng = np.random.default_rng(seed)
    permutation = rng.permutation(total_slots)
    return permutation


def _bytes_to_bits(data: bytes) -> List[int]:
    """Convert bytes to a list of integer bits (0 or 1), MSB first."""
    bits = []
    for b in data:
        for i in range(7, -1, -1):
            bits.append((b >> i) & 1)
    return bits


def _bits_to_bytes(bits: List[int]) -> bytes:
    """Convert list of bits (multiples of 8) back to bytes."""
    byte_vals = []
    for i in range(0, len(bits), 8):
        byte_chunk = bits[i : i + 8]
        val = 0
        for bit in byte_chunk:
            val = (val << 1) | bit
        byte_vals.append(val)
    return bytes(byte_vals)


class DualLayerStego:
    """
    Defensive Dual-Layer Steganography System for Medical Imaging.
    Preserves diagnostic contrast while securely concealing encrypted payloads.
    """

    DEFAULT_STEGO_KEY = "DEFENSIVE_MEDICAL_STEGO_2026"

    @classmethod
    def get_capacity_info(cls, image_path: Union[str, Path, Image.Image]) -> dict:
        """
        Calculate maximum payload capacity for an image.
        """
        img = cls._load_image(image_path)
        w, h = img.size
        channels = len(img.getbands())
        total_slots = w * h * channels
        header_bits = HEADER_SIZE_BYTES * 8

        max_payload_bytes = (total_slots - header_bits) // 8
        return {
            "width": w,
            "height": h,
            "channels": channels,
            "mode": img.mode,
            "total_pixel_slots": total_slots,
            "header_overhead_bytes": HEADER_SIZE_BYTES,
            "max_payload_bytes": max(0, max_payload_bytes),
        }

    @classmethod
    def _load_image(cls, image_input: Union[str, Path, Image.Image]) -> Image.Image:
        """Load and validate image input."""
        if isinstance(image_input, (str, Path)):
            path = Path(image_input)
            if not path.is_file():
                raise InvalidImageError(f"Image file does not exist: {path}")
            try:
                img = Image.open(path)
                img.load()
            except Exception as e:
                raise InvalidImageError(f"Failed to open image file: {e}")
        elif isinstance(image_input, Image.Image):
            img = image_input.copy()
        else:
            raise InvalidImageError(f"Unsupported image type: {type(image_input)}")

        if img.mode not in ("RGB", "L", "RGBA"):
            # Convert palette or other exotic modes to RGB
            img = img.convert("RGB")
        return img

    @classmethod
    def embed_payload(
        cls,
        image_input: Union[str, Path, Image.Image],
        encrypted_payload: bytes,
        stego_key: str | bytes = DEFAULT_STEGO_KEY,
    ) -> Image.Image:
        """
        Embed encrypted payload into image using Dual-Layer Steganography:
        Layer 1: Pseudo-Random Spatial Permutation
        Layer 2: LSB Channel Embedding

        Returns:
            Image.Image: New PIL Image containing the hidden payload.
        """
        if not encrypted_payload:
            raise ValueError("Encrypted payload cannot be empty.")

        img = cls._load_image(image_input)
        img_array = np.array(img, dtype=np.uint8)
        flat_pixels = img_array.reshape(-1)
        total_slots = flat_pixels.shape[0]

        # Construct package: [MAGIC (8B)] + [Payload Len (4B)] + [Encrypted Payload (NB)]
        payload_len = len(encrypted_payload)
        header = MAGIC_HEADER + struct.pack(">I", payload_len)
        full_package = header + encrypted_payload
        bits_to_embed = _bytes_to_bits(full_package)
        total_bits = len(bits_to_embed)

        if total_bits > total_slots:
            raise CapacityExceededError(
                f"Payload size ({len(encrypted_payload)} bytes = {total_bits} bits with header) "
                f"exceeds image capacity ({total_slots} available bits). "
                f"Use a larger image or smaller message."
            )

        # Layer 1: Derive deterministic pseudo-random permutation of all available pixel slots
        permuted_indices = _derive_permutation(total_slots, stego_key)

        # Layer 2: Embed bits into LSB of permuted positions
        selected_indices = permuted_indices[:total_bits]
        for idx, bit in zip(selected_indices, bits_to_embed):
            # Clear LSB (mask 0xFE) and write bit
            flat_pixels[idx] = (flat_pixels[idx] & 0xFE) | bit

        stego_img_array = flat_pixels.reshape(img_array.shape)
        stego_image = Image.fromarray(stego_img_array, mode=img.mode)
        return stego_image

    @classmethod
    def extract_payload(
        cls,
        image_input: Union[str, Path, Image.Image],
        stego_key: str | bytes = DEFAULT_STEGO_KEY,
    ) -> bytes:
        """
        Extract encrypted payload from stego image:
        Reverses Layer 2 (LSB reading) and Layer 1 (spatial unpermuting).

        Returns:
            bytes: Recovered raw encrypted payload.
        """
        img = cls._load_image(image_input)
        img_array = np.array(img, dtype=np.uint8)
        flat_pixels = img_array.reshape(-1)
        total_slots = flat_pixels.shape[0]

        header_bits_count = HEADER_SIZE_BYTES * 8
        if total_slots < header_bits_count:
            raise StegoError("Image is too small to contain a steganography header.")

        # Derive same permutation using stego_key
        permuted_indices = _derive_permutation(total_slots, stego_key)

        # Extract header bits first
        header_slot_indices = permuted_indices[:header_bits_count]
        header_bits = [(flat_pixels[idx] & 1) for idx in header_slot_indices]
        header_bytes = _bits_to_bytes(header_bits)

        magic = header_bytes[: len(MAGIC_HEADER)]
        if magic != MAGIC_HEADER:
            raise StegoError(
                "No valid steganographic payload detected in this image (Magic header mismatch). "
                "The image may not contain hidden data, or an incorrect stego-key was used."
            )

        payload_length = struct.unpack(">I", header_bytes[len(MAGIC_HEADER) : HEADER_SIZE_BYTES])[0]
        total_required_bits = (HEADER_SIZE_BYTES + payload_length) * 8

        if total_required_bits > total_slots:
            raise StegoError(
                f"Corrupted header: declared payload length ({payload_length} bytes) "
                f"exceeds total image capacity ({total_slots} bits)."
            )

        # Extract payload bits
        payload_slot_indices = permuted_indices[header_bits_count:total_required_bits]
        payload_bits = [(flat_pixels[idx] & 1) for idx in payload_slot_indices]
        encrypted_payload = _bits_to_bytes(payload_bits)

        return encrypted_payload
