# Advanced Cybersecurity Weekly Projects

A production-grade, academic curriculum featuring three end-to-end cybersecurity projects designed for Bachelor of Computer Applications (BCA) and Master's cybersecurity demonstrations, practical labs, and viva evaluation.

---

## Curriculum Overview

| Week | Project Title | Primary Cryptographic Primitives | Key Security Concepts |
|:---:|:---|:---|:---|
| **Week 1** | **Cryptographically Secure Pseudo-Random Number Generator (CSPRNG)** | ChaCha20 (RFC 8439), OS Kernel Entropy Pool, SHA-256 | Entropy, Nonces, Rejection Sampling (Zero Modulo Bias), Forward Secrecy / Ratcheting, Mersenne Twister (MT19937) Inversion Attack |
| **Week 2** | **Dual-Layer Steganography for Medical Imaging** | AES-256-GCM, PBKDF2-HMAC-SHA256, Spatial Permutations | Authenticated Encryption (AEAD), Anti-Steganalysis Randomized Embedding, LSB Modulation, PSNR & MSE Analysis, HIPAA-Safe Synthetic Phantoms |
| **Week 3** | **Post-Quantum Stateless Hash-Based Signatures (SPHINCS+)** | SLH-DSA (NIST FIPS 205), SHA-256 / SHAKE-128, Hypertree | Quantum Resistance, Shor's & Grover's Algorithms, Stateless Hypertree vs Stateful XMSS/LMS, FORS Few-Time Signatures, WOTS+ |

---

## Directory Organization

```
Cybersecurity_Weekly_Projects/
│
├── pytest.ini                            # Master pytest configuration
├── requirements.txt                      # Consolidated dependencies
├── README.md                             # Master curriculum guide
├── PROJECT_REPORT.md                     # Comprehensive 18-chapter academic project report
│
├── Week_1_CSPRNG_ChaCha20/               # WEEK 1: CSPRNG using ChaCha20
│   ├── src/
│   │   ├── __init__.py
│   │   ├── csprng.py                     # ChaCha20 engine & rejection sampling
│   │   ├── stats.py                      # NIST SP 800-22 statistical sanity suite
│   │   └── comparison.py                 # Live MT19937 state reconstruction attack
│   ├── tests/
│   │   └── test_csprng.py                # 14 automated unit tests
│   ├── docs/
│   │   ├── architecture.md
│   │   ├── algorithm.md
│   │   ├── security.md
│   │   └── testing.md
│   ├── demo/
│   │   └── demo_csprng.py                # End-to-end interactive demo
│   ├── requirements.txt
│   ├── README.md
│   └── run.py                            # CLI tool
│
├── Week_2_Dual_Layer_Steganography_AES256/ # WEEK 2: Dual-Layer Medical Steganography
│   ├── src/
│   │   ├── __init__.py
│   │   ├── crypto.py                     # AES-256-GCM + PBKDF2 engine
│   │   ├── stego.py                      # Spatial permutation + LSB modulation
│   │   ├── image_metrics.py              # PSNR, MSE, and pixel distortion metrics
│   │   └── sample_generator.py           # Synthetic Brain MRI & Chest X-Ray phantoms
│   ├── tests/
│   │   ├── test_crypto.py                # AES-256-GCM security unit tests
│   │   └── test_stego.py                 # Steganography & image fidelity tests
│   ├── sample_data/
│   │   └── input.png                     # Synthetic medical cover image
│   ├── output/
│   │   └── .gitkeep                      # Destination for stego and decrypted outputs
│   ├── docs/
│   │   ├── architecture.md
│   │   ├── algorithm.md
│   │   ├── security.md
│   │   └── testing.md
│   ├── demo/
│   │   └── demo_stego.py                 # End-to-end medical steganography demo
│   ├── requirements.txt
│   ├── README.md
│   └── run.py                            # CLI tool
│
└── Week_3_SPHINCS_Plus/                  # WEEK 3: Post-Quantum SPHINCS+ (SLH-DSA)
    ├── src/
    ├── src/
    │   ├── __init__.py
    │   ├── sphincs_engine.py             # NIST FIPS 205 keygen, sign, verify engine
    │   └── metadata.py                   # Parameter sets and quantum threat analysis
    ├── tests/
    │   └── test_sphincs.py               # 10 post-quantum unit tests
    ├── docs/
    │   ├── architecture.md
    │   ├── algorithm.md
    │   ├── security.md
    │   └── testing.md
    ├── demo/
    │   └── demo_sphincs.py               # Post-quantum signature lifecycle demo
    ├── requirements.txt
    ├── README.md
    └── run.py                            # CLI tool
```

---

## Installation & Setup

All three projects use standard Python 3.10+ (tested on Python 3.13 on Windows).

```powershell
# 1. Navigate to the master project directory
cd Cybersecurity_Weekly_Projects

# 2. Install all dependencies
pip install -r requirements.txt
```

---

## Running the Automated Test Suite

A single pytest execution from the parent folder automatically executes all 37 test suites across all three weekly projects:

```powershell
pytest
```

Expected Output:
```
============================= test session starts =============================
collected 37 items

Week_1_CSPRNG_ChaCha20/tests/test_csprng.py::TestChaCha20CSPRNG ... PASSED [ 37%]
Week_2_Dual_Layer_Steganography_AES256/tests/test_crypto.py ...    PASSED [ 54%]
Week_2_Dual_Layer_Steganography_AES256/tests/test_stego.py ...     PASSED [ 72%]
Week_3_SPHINCS_Plus/tests/test_sphincs.py ...                      PASSED [100%]

============================= 37 passed in 5.85s ==============================
```

---

## Quick-Start Demonstration Guide

### Week 1: ChaCha20 CSPRNG
```powershell
# Generate 32 cryptographically secure random bytes
python Week_1_CSPRNG_ChaCha20/run.py --bytes 32

# Generate an unbiased random integer (1 to 100,000) using rejection sampling
python Week_1_CSPRNG_ChaCha20/run.py --integer 1 100000

# Demonstrate Mersenne Twister state reconstruction attack vs ChaCha20
python Week_1_CSPRNG_ChaCha20/run.py --compare

# Run NIST SP 800-22 statistical sanity suite on 50,000 bytes
python Week_1_CSPRNG_ChaCha20/run.py --stats 50000

# Run full end-to-end interactive demo
python Week_1_CSPRNG_ChaCha20/run.py --demo
```

### Week 2: Dual-Layer Medical Steganography
```powershell
# 1. Generate a synthetic HIPAA-safe Brain MRI phantom image
python Week_2_Dual_Layer_Steganography_AES256/run.py generate-sample --type mri --output Week_2_Dual_Layer_Steganography_AES256/sample_data/input.png

# 2. Encrypt medical diagnosis with AES-256-GCM and embed into cover image
python Week_2_Dual_Layer_Steganography_AES256/run.py encode \
  --image Week_2_Dual_Layer_Steganography_AES256/sample_data/input.png \
  --message "CONFIDENTIAL: Biopsy findings negative for malignancy." \
  --output Week_2_Dual_Layer_Steganography_AES256/output/stego.png \
  --password "MedicalSecPass2026!"

# 3. Analyze image fidelity (PSNR & MSE)
python Week_2_Dual_Layer_Steganography_AES256/run.py metrics \
  --original Week_2_Dual_Layer_Steganography_AES256/sample_data/input.png \
  --stego Week_2_Dual_Layer_Steganography_AES256/output/stego.png

# 4. Extract and authenticate hidden medical record
python Week_2_Dual_Layer_Steganography_AES256/run.py decode \
  --image Week_2_Dual_Layer_Steganography_AES256/output/stego.png \
  --password "MedicalSecPass2026!"

# 5. Run full end-to-end demo (including wrong-password and tamper defense tests)
python Week_2_Dual_Layer_Steganography_AES256/run.py demo
```

### Week 3: Post-Quantum SPHINCS+ (SLH-DSA)
```powershell
# 1. Display algorithm metadata, NIST FIPS 205 specs, and quantum threat breakdown
python Week_3_SPHINCS_Plus/run.py info

# 2. Generate a post-quantum keypair (32-byte public key, 64-byte secret key)
python Week_3_SPHINCS_Plus/run.py keygen --out-dir Week_3_SPHINCS_Plus/demo --prefix sphincs

# 3. Sign a file using the post-quantum secret key
python Week_3_SPHINCS_Plus/run.py sign \
  --file Week_3_SPHINCS_Plus/requirements.txt \
  --key Week_3_SPHINCS_Plus/demo/sphincs_secret.key \
  --sig Week_3_SPHINCS_Plus/demo/sig.bin

# 4. Verify signature authenticity with public key
python Week_3_SPHINCS_Plus/run.py verify \
  --file Week_3_SPHINCS_Plus/requirements.txt \
  --key Week_3_SPHINCS_Plus/demo/sphincs_public.key \
  --sig Week_3_SPHINCS_Plus/demo/sig.bin

# 5. Measure keygen, sign, and verify latency
python Week_3_SPHINCS_Plus/run.py benchmark --iterations 3

# 6. Run full post-quantum demonstration
python Week_3_SPHINCS_Plus/run.py demo
```

---

## Academic Viva Voce Key Pointers

1. **Why is `random.randint()` or `random.random()` insecure?**
   - Python's standard `random` uses the Mersenne Twister (MT19937). It is completely deterministic and reversible. Observing 624 32-bit integers allows an attacker to reconstruct the entire 19,937-bit state and predict all future numbers.
2. **What is Modulo Bias, and how is it eliminated?**
   - Modulo bias occurs when calculating `rand() % R` where the domain size is not evenly divisible by $R$. It biases outputs toward smaller numbers. Rejection sampling eliminates this by discarding numbers above the largest multiple of $R$.
3. **What is the difference between Steganography and Cryptography?**
   - Cryptography protects confidentiality (scrambles plaintext into unreadable ciphertext). Steganography conceals the existence of the message. In Week 2, both are combined: AES-256-GCM provides confidentiality and tamper detection, while steganography conceals the transmission.
4. **Why is AES-GCM preferred over AES-CBC or AES-ECB?**
   - AES-ECB does not hide patterns (e.g. ECB penguin). AES-CBC provides confidentiality but no integrity, making it vulnerable to padding oracles and bit-flipping. AES-GCM is an AEAD cipher that generates a 128-bit authentication tag, detecting any unauthorized bit modifications.
5. **How does Shor's Algorithm threaten RSA and ECC?**
   - Shor's algorithm solves discrete logarithms and prime factorizations in polynomial time $\mathcal{O}((\log N)^3)$, instantly breaking RSA and ECC.
6. **Why are Hash-Based Signatures (SPHINCS+ / SLH-DSA) quantum-safe?**
   - Hash functions do not rely on hidden subgroup problems. Quantum speedup against hash functions is limited to Grover's algorithm ($\mathcal{O}(\sqrt{N})$), which halves effective security. Using 256-bit hashes leaves 128 bits of quantum security.
7. **What is the difference between Stateful (XMSS/LMS) and Stateless (SPHINCS+) signatures?**
   - Stateful schemes maintain a counter of used keys; rolling back state (e.g., VM backup restore) results in key reuse and immediate signature forgery. SPHINCS+ uses a massive hypertree ($2^{66}$ leaves) with randomized few-time signatures (FORS), making key reuse mathematically impossible without tracking state.
