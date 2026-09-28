"""
Week 3: Post-Quantum Stateless Hash-Based Signatures Using SPHINCS+ (SLH-DSA).
"""

from .sphincs_engine import SphincsEngine, SphincsKeyPair, SphincsError
from .metadata import get_algorithm_metadata, SPHINCS_PARAMETER_SETS

__all__ = [
    "SphincsEngine",
    "SphincsKeyPair",
    "SphincsError",
    "get_algorithm_metadata",
    "SPHINCS_PARAMETER_SETS",
]
