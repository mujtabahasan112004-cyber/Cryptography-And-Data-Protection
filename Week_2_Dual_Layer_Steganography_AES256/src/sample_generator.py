"""
Synthetic Medical Image Generator for Non-Sensitive Academic Research.

Produces synthetic diagnostic-style phantom images (Brain MRI & Chest X-Ray)
to comply with HIPAA/GDPR ethical requirements while providing realistic
multidimensional arrays for steganographic experiments.
"""

from __future__ import annotations

import math
from pathlib import Path
from typing import Optional, Union

import numpy as np
from PIL import Image, ImageDraw, ImageFilter


def generate_synthetic_mri(
    width: int = 512,
    height: int = 512,
    output_path: Optional[Union[str, Path]] = None,
) -> Image.Image:
    """
    Generate a synthetic Brain MRI axial slice phantom image.
    Features: Skull ellipse, CSF ventricles, brain parenchyma, and subtle textural gradients.
    """
    # Create coordinate grid
    y, x = np.ogrid[:height, :width]
    center_y, center_x = height / 2.0, width / 2.0

    # Normalized distance from center
    norm_y = (y - center_y) / (height * 0.42)
    norm_x = (x - center_x) / (width * 0.35)
    dist_sq = norm_x ** 2 + norm_y ** 2

    # Canvas buffer
    canvas = np.zeros((height, width), dtype=np.float32)

    # 1. Skull bone (outer ring)
    skull_mask = (dist_sq <= 1.05) & (dist_sq >= 0.95)
    canvas[skull_mask] = 180.0

    # 2. Brain parenchyma (cortex and subcortical tissue)
    brain_mask = dist_sq < 0.95
    # Radial falloff + undulating gyri texture
    gyri = np.sin(x * 0.15) * np.cos(y * 0.15) * 12.0
    parenchyma = 120.0 - (dist_sq * 40.0) + gyri
    canvas[brain_mask] = parenchyma[brain_mask]

    # 3. Ventricles (central CSF butterfly cavity - darker)
    v_norm_y = (y - center_y) / (height * 0.15)
    v_norm_x_left = (x - (center_x - width * 0.05)) / (width * 0.04)
    v_norm_x_right = (x - (center_x + width * 0.05)) / (width * 0.04)
    ventricle_mask = (v_norm_x_left ** 2 + v_norm_y ** 2 < 1.0) | (
        v_norm_x_right ** 2 + v_norm_y ** 2 < 1.0
    )
    canvas[ventricle_mask] = 35.0

    # 4. Add subtle thermal sensor noise
    rng = np.random.default_rng(42)
    noise = rng.normal(0, 3.0, (height, width))
    canvas = np.clip(canvas + noise, 0, 255).astype(np.uint8)

    img = Image.fromarray(canvas, mode="L").convert("RGB")
    # Smooth slightly to mimic magnetic resonance reconstruction
    img = img.filter(ImageFilter.GaussianBlur(radius=0.7))

    if output_path:
        out_p = Path(output_path)
        out_p.parent.mkdir(parents=True, exist_ok=True)
        img.save(out_p, format="PNG")

    return img


def generate_synthetic_xray(
    width: int = 512,
    height: int = 512,
    output_path: Optional[Union[str, Path]] = None,
) -> Image.Image:
    """
    Generate a synthetic Chest Radiograph (CXR) phantom image.
    Features: Thoracic cage, bilateral radiolucent lung fields, mediastinum, and cardiac silhouette.
    """
    canvas = np.full((height, width), 210.0, dtype=np.float32)
    y, x = np.ogrid[:height, :width]
    center_y, center_x = height / 2.0, width / 2.0

    # 1. Bilateral Lung Fields (dark radiolucent areas)
    left_lung_dist = ((x - (center_x - width * 0.22)) / (width * 0.18)) ** 2 + (
        (y - (center_y - height * 0.05)) / (height * 0.35)
    ) ** 2
    right_lung_dist = ((x - (center_x + width * 0.22)) / (width * 0.18)) ** 2 + (
        (y - (center_y - height * 0.05)) / (height * 0.35)
    ) ** 2

    canvas[left_lung_dist < 1.0] = 50.0 + (left_lung_dist[left_lung_dist < 1.0] * 40.0)
    canvas[right_lung_dist < 1.0] = 50.0 + (right_lung_dist[right_lung_dist < 1.0] * 40.0)

    # 2. Cardiac Silhouette (heart shadow in left hemithorax)
    heart_dist = ((x - (center_x - width * 0.06)) / (width * 0.16)) ** 2 + (
        (y - (center_y + height * 0.08)) / (height * 0.18)
    ) ** 2
    canvas[heart_dist < 1.0] = np.maximum(canvas[heart_dist < 1.0], 170.0)

    # 3. Rib shadows (horizontal curved radio-opacities)
    ribs = np.sin((y + 0.05 * (x - center_x) ** 2 / width) * 0.08)
    canvas += ribs * 20.0

    # 4. Add sensor noise
    rng = np.random.default_rng(101)
    noise = rng.normal(0, 4.0, (height, width))
    canvas = np.clip(canvas + noise, 0, 255).astype(np.uint8)

    img = Image.fromarray(canvas, mode="L").convert("RGB")
    img = img.filter(ImageFilter.GaussianBlur(radius=0.5))

    if output_path:
        out_p = Path(output_path)
        out_p.parent.mkdir(parents=True, exist_ok=True)
        img.save(out_p, format="PNG")

    return img
