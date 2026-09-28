"""
Image Quality and Steganographic Fidelity Analysis Module.

Calculates:
- Mean Squared Error (MSE)
- Peak Signal-to-Noise Ratio (PSNR in dB)
- Mean Absolute Error (MAE)
- Maximum Pixel Delta
- Percentage of Modified Pixels

ACADEMIC NOTE ON MEDICAL IMAGING STEGANOGRAPHY:
In diagnostic imaging (CT, MRI, X-ray), alterations to pixel intensities can
influence diagnostic decisions or automated classification models.
High PSNR (> 50 dB) indicates that the changes are confined to sub-visual LSB noise,
leaving diagnostic features intact.
"""

from __future__ import annotations

import math
from dataclasses import dataclass
from pathlib import Path
from typing import Union

import numpy as np
from PIL import Image


@dataclass
class ImageQualityMetrics:
    mse: float
    psnr: float
    mae: float
    max_delta: int
    modified_pixels_count: int
    total_pixels_count: int
    modified_percentage: float
    fidelity_assessment: str


def compute_image_metrics(
    image1_input: Union[str, Path, Image.Image],
    image2_input: Union[str, Path, Image.Image],
) -> ImageQualityMetrics:
    """
    Compare original cover image and stego image to compute fidelity metrics.
    """
    def _to_array(inp: Union[str, Path, Image.Image]) -> np.ndarray:
        if isinstance(inp, (str, Path)):
            img = Image.open(inp)
            img.load()
        else:
            img = inp
        return np.array(img, dtype=np.float64)

    arr1 = _to_array(image1_input)
    arr2 = _to_array(image2_input)

    if arr1.shape != arr2.shape:
        raise ValueError(f"Image shapes do not match: {arr1.shape} vs {arr2.shape}")

    diff = arr1 - arr2
    abs_diff = np.abs(diff)

    mse = float(np.mean(diff ** 2))
    mae = float(np.mean(abs_diff))
    max_delta = int(np.max(abs_diff))

    total_elements = arr1.size
    modified_count = int(np.count_nonzero(abs_diff))
    modified_pct = (modified_count / total_elements) * 100.0

    if mse == 0.0:
        psnr = float("inf")
        assessment = "Identical Images (Zero Distortion)"
    else:
        # Max pixel value for 8-bit image is 255.0
        max_i = 255.0
        psnr = float(10.0 * math.log10((max_i ** 2) / mse))
        if psnr >= 60.0:
            assessment = "Exceptional Fidelity (Invisible to Human Eye & Clinical Radiologists)"
        elif psnr >= 50.0:
            assessment = "High Fidelity (Diagnostic Boundaries Preserved)"
        elif psnr >= 40.0:
            assessment = "Moderate Quality (Minor Sub-Visual Noise)"
        else:
            assessment = "Degraded Fidelity (Noticeable Artifacts)"

    return ImageQualityMetrics(
        mse=mse,
        psnr=psnr,
        mae=mae,
        max_delta=max_delta,
        modified_pixels_count=modified_count,
        total_pixels_count=total_elements,
        modified_percentage=modified_pct,
        fidelity_assessment=assessment,
    )
