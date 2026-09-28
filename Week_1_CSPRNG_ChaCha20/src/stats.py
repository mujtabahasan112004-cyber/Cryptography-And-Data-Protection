"""
Statistical Sanity Testing Suite for Random Number Generators.

Contains standard empirical tests:
1. Shannon Entropy
2. Monobit / Frequency Test
3. Runs Test
4. Chi-Square Goodness-of-Fit Test

ACADEMIC NOTE ON CRYPTOGRAPHIC SECURITY:
Passing statistical tests is a NECESSARY condition for a CSPRNG, but it is NOT
a SUFFICIENT condition. Completely deterministic, non-cryptographic sequences
(such as the decimal expansion of Pi, or a simple counter encrypted with an insecure key)
can pass statistical randomness tests with flying colors while offering ZERO prediction
resistance. True cryptographic security depends on the computational hardness of inverting
the underlying primitive (ChaCha20).
"""

from __future__ import annotations

import math
from dataclasses import dataclass
from typing import Dict, List, Tuple


@dataclass
class TestResult:
    name: str
    statistic: float
    p_value: float
    passed: bool
    description: str
    detail: str


@dataclass
class StatisticalReport:
    sample_size_bytes: int
    shannon_entropy: float
    max_entropy: float
    results: List[TestResult]
    all_passed: bool
    disclaimer: str


def compute_shannon_entropy(data: bytes) -> float:
    """
    Compute Shannon entropy in bits per byte (max: 8.0 bits/byte).
    H(X) = - sum(p(x) * log2(p(x)))
    """
    if not data:
        return 0.0

    counts = [0] * 256
    for b in data:
        counts[b] += 1

    total = len(data)
    entropy = 0.0
    for c in counts:
        if c > 0:
            p = c / total
            entropy -= p * math.log2(p)
    return entropy


def monobit_frequency_test(data: bytes, alpha: float = 0.01) -> TestResult:
    """
    NIST SP 800-22 Monobit Frequency Test.
    Tests whether the number of ones and zeros in the bitstream are approximately equal.
    """
    total_bits = len(data) * 8
    if total_bits == 0:
        return TestResult("Monobit Frequency Test", 0.0, 0.0, False, "Zero-length sample", "")

    # Count ones
    ones = sum(bin(b).count("1") for b in data)
    zeros = total_bits - ones
    s_n = ones - zeros
    s_obs = abs(s_n) / math.sqrt(total_bits)

    # p-value = erfc(s_obs / sqrt(2))
    p_value = math.erfc(s_obs / math.sqrt(2))
    passed = p_value >= alpha

    return TestResult(
        name="Monobit Frequency Test",
        statistic=float(s_obs),
        p_value=float(p_value),
        passed=passed,
        description="Checks bit uniformity: balance between 0 and 1 bits.",
        detail=f"Total bits: {total_bits}, Ones: {ones}, Zeros: {zeros}, S_obs: {s_obs:.4f}",
    )


def runs_test(data: bytes, alpha: float = 0.01) -> TestResult:
    """
    NIST SP 800-22 Runs Test.
    Tests whether the oscillation between sequences of ones and zeros is typical of a random sequence.
    """
    total_bits = len(data) * 8
    if total_bits < 100:
        return TestResult("Runs Test", 0.0, 0.0, False, "Sample too small (need >= 100 bits)", "")

    # Convert bytes to bit array
    bits = []
    for b in data:
        for shift in range(7, -1, -1):
            bits.append((b >> shift) & 1)

    ones = sum(bits)
    pi_prop = ones / total_bits

    # Pre-test frequency requirement
    if abs(pi_prop - 0.5) >= (2.0 / math.sqrt(total_bits)):
        return TestResult(
            name="Runs Test",
            statistic=0.0,
            p_value=0.0,
            passed=False,
            description="Runs test failed pre-requisite frequency proportion.",
            detail=f"Proportion pi = {pi_prop:.4f} diverges from 0.5",
        )

    # Count runs (transitions + 1)
    runs = 1 + sum(1 for i in range(total_bits - 1) if bits[i] != bits[i + 1])

    # Expected runs
    expected_runs = 2.0 * total_bits * pi_prop * (1.0 - pi_prop)
    variance = (
        2.0 * math.sqrt(2.0 * total_bits) * pi_prop * (1.0 - pi_prop)
    )

    if variance == 0:
        return TestResult("Runs Test", 0.0, 0.0, False, "Zero variance in runs", "")

    z = abs(runs - expected_runs) / variance
    p_value = math.erfc(z / math.sqrt(2))
    passed = p_value >= alpha

    return TestResult(
        name="Runs Test",
        statistic=float(z),
        p_value=float(p_value),
        passed=passed,
        description="Evaluates the total number of runs of uninterrupted identical bits.",
        detail=f"Observed runs: {runs}, Expected: {expected_runs:.1f}, Z-score: {z:.4f}",
    )


def chi_square_test(data: bytes, alpha: float = 0.01) -> TestResult:
    """
    Chi-Square Goodness-of-Fit Test on 256 byte values.
    Tests whether byte values [0..255] are uniformly distributed.
    Degrees of freedom = 255.
    """
    total = len(data)
    if total < 1024:
        return TestResult(
            name="Chi-Square Uniformity Test",
            statistic=0.0,
            p_value=0.0,
            passed=False,
            description="Sample too small for 256-bin Chi-Square (need >= 1024 bytes)",
            detail=f"Sample size: {total} bytes",
        )

    counts = [0] * 256
    for b in data:
        counts[b] += 1

    expected = total / 256.0
    chi_square = sum(((observed - expected) ** 2) / expected for observed in counts)

    # Approximation of p-value for chi-square with df=255
    # Wilson-Hilferty transformation:
    # z = ( (chi_square / df)^(1/3) - (1 - 2/(9*df)) ) / sqrt(2/(9*df))
    df = 255.0
    s_factor = math.pow(chi_square / df, 1.0 / 3.0)
    mu = 1.0 - (2.0 / (9.0 * df))
    sigma = math.sqrt(2.0 / (9.0 * df))
    z = (s_factor - mu) / sigma

    # Standard normal two-tailed p-value
    p_value = 0.5 * math.erfc(abs(z) / math.sqrt(2)) * 2.0
    passed = p_value >= alpha

    return TestResult(
        name="Chi-Square Uniformity Test",
        statistic=float(chi_square),
        p_value=float(p_value),
        passed=passed,
        description="Checks if all 256 byte values occur with uniform frequency.",
        detail=f"Chi2 statistic: {chi_square:.2f} (df=255), Expected/bin: {expected:.1f}",
    )


def run_statistical_tests(data: bytes) -> StatisticalReport:
    """
    Execute all statistical sanity tests on a given byte sample.
    """
    entropy = compute_shannon_entropy(data)
    t_monobit = monobit_frequency_test(data)
    t_runs = runs_test(data)
    t_chi2 = chi_square_test(data)

    results = [t_monobit, t_runs, t_chi2]
    all_passed = all(r.passed for r in results) and (entropy >= 7.9)

    disclaimer = (
        "IMPORTANT SECURITY NOTICE:\n"
        "Statistical tests evaluate empirical distribution uniformity and local randomness.\n"
        "They CANNOT prove cryptographic security or unpredictability.\n"
        "Predictable generators (like LCG or Mersenne Twister) can pass these tests,\n"
        "yet remain totally insecure against cryptographic attacks."
    )

    return StatisticalReport(
        sample_size_bytes=len(data),
        shannon_entropy=entropy,
        max_entropy=8.0,
        results=results,
        all_passed=all_passed,
        disclaimer=disclaimer,
    )
