# Testing Strategy & Test Case Documentation: ChaCha20 CSPRNG

## 1. Overview
The testing framework for the ChaCha20 CSPRNG combines automated unit tests, property checks, edge-case validation, statistical sanity verification, and live vulnerability reproduction.

## 2. Test Execution
To run all tests for Week 1:
```powershell
pytest Week_1_CSPRNG_ChaCha20/tests -v
```

## 3. Test Matrix

| Test Identifier | Category | Objective | Pass Criterion |
|---|---|---|---|
| `test_output_lengths` | Correctness | Verify `random_bytes(N)` returns exactly $N$ bytes for varied $N$. | Returned bytes length matches $N$ exactly. |
| `test_output_uniqueness_across_calls` | Entropy | Generate 50 consecutive 32-byte blocks. | Set cardinality is 50 (zero collisions). |
| `test_output_uniqueness_across_instances` | Seeding | Instantiate two independent CSPRNG objects. | Output streams differ. |
| `test_integer_range_correctness` | Bounding | Generate 200 random integers across ranges $[min, max]$. | Every integer $x$ satisfies $min \le x \le max$. |
| `test_integer_range_boundary_values` | Edge Case | Test $min == max$, negative spans, zero-crossing spans. | Exact output returned without hanging or error. |
| `test_integer_distribution_coverage` | Uniformity | Simulate 100 die rolls in range $[1, 6]$. | All six faces are observed. |
| `test_random_hex_format` | Format | Verify hex token character set and length. | Length is $2N$, matches regex `^[0-9a-f]+$`. |
| `test_random_urlsafe_format` | Format | Verify URL-safe base64 token format. | Matches `^[A-Za-z0-9_-]+$`, no `=` padding. |
| `test_reseeding` | State | Call `reseed()` and observe diagnostic counter. | Reseed counter increments, generator operational. |
| `test_auto_ratcheting_on_threshold` | Forward Secrecy | Set reseed threshold low (128B), generate past limit. | Ratchet triggers, state resets counter smoothly. |
| `test_invalid_arguments_raise_errors` | Input Validation | Pass negative lengths, non-integer types, inverted ranges. | Raises `ValueError` or `TypeError`. |
| `test_shannon_entropy_calculation` | Sanity | Test entropy on known distributions (all bytes vs uniform). | Uniform = 8.0, All zeros = 0.0 bits/byte. |
| `test_csprng_passes_statistical_sanity` | Empirical | Run NIST SP 800-22 subset on 30,000 bytes. | Shannon entropy $> 7.95$, Monobit, Runs, Chi2 pass. |
| `test_mersenne_twister_cloning` | Vulnerability | Reconstruct Python `random` internal state from 624 outputs. | Cloned generator matches 100% of future outputs. |

## 4. Statistical Sanity Benchmark
The statistical sanity suite evaluates 50,000 bytes against three empirical tests:
1. **Monobit Test**: Checks bit proportion. Target $p\text{-value} \ge 0.01$.
2. **Runs Test**: Checks consecutive bit oscillation. Target $p\text{-value} \ge 0.01$.
3. **Chi-Square Goodness-of-Fit**: Checks uniform distribution of all 256 byte values. Target $p\text{-value} \ge 0.01$.
