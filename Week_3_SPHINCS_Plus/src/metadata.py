"""
Post-Quantum Cryptography & SPHINCS+ / SLH-DSA Architectural Metadata.

Provides educational parameters, quantum threat analysis, and mathematical specifications
for NIST FIPS 205 (Stateless Hash-Based Digital Signature Algorithm - SLH-DSA).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, Any


@dataclass
class ParameterSetInfo:
    name: str
    standard_name: str
    security_category: int
    security_level_bits: int
    hash_function: str
    optimization: str
    n_bytes: int             # Security parameter n
    h_tree_height: int       # Total hypertree height h
    d_layers: int            # Number of tree layers d
    b_fors_height: int       # FORS tree height b
    k_fors_trees: int        # Number of FORS trees k
    w_wots_param: int        # Winternitz parameter w
    public_key_bytes: int    # Public key size (2 * n)
    secret_key_bytes: int    # Secret key size (4 * n)
    signature_bytes: int     # Signature size
    stateless: bool


SPHINCS_PARAMETER_SETS: Dict[str, ParameterSetInfo] = {
    "slhdsa-sha2-128f": ParameterSetInfo(
        name="SPHINCS+-SHA2-128f",
        standard_name="SLH-DSA-SHA2-128f (NIST FIPS 205)",
        security_category=1,
        security_level_bits=128,
        hash_function="SHA-256",
        optimization="Fast (larger signature, faster signing)",
        n_bytes=16,
        h_tree_height=66,
        d_layers=22,
        b_fors_height=6,
        k_fors_trees=33,
        w_wots_param=16,
        public_key_bytes=32,
        secret_key_bytes=64,
        signature_bytes=17088,
        stateless=True,
    ),
    "slhdsa-shake-128f": ParameterSetInfo(
        name="SPHINCS+-SHAKE-128f",
        standard_name="SLH-DSA-SHAKE-128f (NIST FIPS 205)",
        security_category=1,
        security_level_bits=128,
        hash_function="SHAKE-128 (Keccak)",
        optimization="Fast (larger signature, faster signing)",
        n_bytes=16,
        h_tree_height=66,
        d_layers=22,
        b_fors_height=6,
        k_fors_trees=33,
        w_wots_param=16,
        public_key_bytes=32,
        secret_key_bytes=64,
        signature_bytes=17088,
        stateless=True,
    ),
    "slhdsa-sha2-128s": ParameterSetInfo(
        name="SPHINCS+-SHA2-128s",
        standard_name="SLH-DSA-SHA2-128s (NIST FIPS 205)",
        security_category=1,
        security_level_bits=128,
        hash_function="SHA-256",
        optimization="Small (smaller signature, slower signing)",
        n_bytes=16,
        h_tree_height=63,
        d_layers=7,
        b_fors_height=12,
        k_fors_trees=14,
        w_wots_param=16,
        public_key_bytes=32,
        secret_key_bytes=64,
        signature_bytes=7856,
        stateless=True,
    ),
}


def get_algorithm_metadata(param_set: str = "slhdsa-sha2-128f") -> Dict[str, Any]:
    """
    Return comprehensive educational dossier on SPHINCS+ / SLH-DSA.
    """
    param = SPHINCS_PARAMETER_SETS.get(param_set, SPHINCS_PARAMETER_SETS["slhdsa-sha2-128f"])

    return {
        "parameters": {
            "parameter_set": param.name,
            "nist_standard": param.standard_name,
            "security_category": f"NIST Category {param.security_category} (equivalent to AES-128 classical and quantum security)",
            "hash_function": param.hash_function,
            "design_profile": param.optimization,
            "public_key_size_bytes": param.public_key_bytes,
            "secret_key_size_bytes": param.secret_key_bytes,
            "signature_size_bytes": f"{param.signature_bytes:,} bytes (~{param.signature_bytes / 1024:.1f} KB)",
            "hypertree_total_height_h": param.h_tree_height,
            "hypertree_layers_d": param.d_layers,
            "xmss_subtree_height": param.h_tree_height // param.d_layers,
            "fors_trees_k": param.k_fors_trees,
            "fors_height_b": param.b_fors_height,
            "wots_plus_parameter_w": param.w_wots_param,
        },
        "quantum_threat_breakdown": {
            "shors_algorithm": (
                "Peter Shor (1994) formulated a quantum algorithm running in polynomial time O((log N)^3) "
                "that calculates discrete logarithms and prime factorizations. "
                "A cryptanalytically relevant quantum computer (CRQC) will completely break RSA, DSA, "
                "ECDSA (secp256k1, NIST P-256), and Ed25519."
            ),
            "grovers_algorithm": (
                "Lov Grover (1996) formulated a quantum search algorithm providing quadratic speedup O(sqrt(N)). "
                "For symmetric ciphers and cryptographic hash functions, Grover's algorithm halves effective bit security. "
                "A 256-bit hash function (like SHA-256) still retains 128 bits of quantum security against Grover, "
                "requiring no fundamental design changes beyond standard key sizes."
            ),
        },
        "why_hash_based_signatures": (
            "Hash-based signatures are the oldest and most trusted family of post-quantum cryptography. "
            "Unlike lattice-based (ML-DSA) or multivariate schemes, hash-based signatures do NOT rely on unproven "
            "algebraic hardness assumptions. Their security relies solely on the standard security properties of "
            "cryptographic hash functions (collision resistance, second-preimage resistance, and pseudo-randomness)."
        ),
        "stateless_vs_stateful": (
            "Stateful hash-based signatures (e.g., XMSS / LMS) maintain an internal counter tracking which one-time "
            "keys have been consumed. If the counter is rolled back (via virtual machine snapshot, backup restore, or "
            "system crash), the same private key is used twice, resulting in catastrophic and permanent signature forgery.\n"
            "SPHINCS+ / SLH-DSA solves this permanently by being completely STATELESS. By utilizing a massive hypertree "
            "(2^66 leaves) and randomized few-time signatures (FORS), the probability of colliding on the same one-time "
            "key is less than 2^-128 over any practical signing volume."
        ),
    }
