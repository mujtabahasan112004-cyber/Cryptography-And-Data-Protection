# Security Analysis & Defensive Properties: Dual-Layer Medical Stego

## 1. Threat Model
We assume an active adversary $\mathcal{A}$ monitoring network traffic between a hospital PACS node and an imaging analysis clinic.
$\mathcal{A}$ has the following potential vectors:
1. **Passive Steganalysis**: Running statistical tools (Chi-square test, sample pairs analysis, histogram difference) to detect whether an image contains hidden data.
2. **Ciphertext Manipulation (Bit-Flipping)**: Intercepting the image and maliciously altering pixel bits to falsify diagnoses or dosages.
3. **Password Guessing / Offline Brute-Force**: Extracting the steganographic payload and running GPU dictionaries to crack the passphrase.

---

## 2. Mitigations & Defense Mechanisms

### 2.1 Spatial Scattering vs. Steganalysis
Traditional LSB steganography embeds bits consecutively along pixel rows:
- Produces anomalous runs of altered LSBs.
- Vulnerable to the **Westfeld-Pfitzmann Chi-Square attack**, which examines pairs of values $(2k, 2k+1)$ whose frequencies equalize under sequential LSB embedding.
- **Our Defense**: Layer 1 distributes bits across pseudo-random coordinates using the Fisher-Yates permutation. The altered pixels are distributed globally with extremely low density ($\approx 0.05\% - 0.2\%$ of total pixels for typical reports). The global histogram and spatial auto-correlation remain statistically normal.

### 2.2 Rejection of Forgeries & Bit-Flipping via AES-GCM
In unauthenticated ciphers (e.g. standard CBC or CTR mode), an attacker can flip specific ciphertext bits to predictably alter decrypted plaintext (e.g. changing `"Benign"` to `"Malign"`).
- **Our Defense**: AES-256-GCM produces a 128-bit authentication tag $T$ computed over the ciphertext, nonce, and associated data. If an adversary flips even a single bit in the stego image covering the payload, the GHASH verification fails with probability $1 - 2^{-128}$. Decryption raises `AuthenticationFailedError` and outputs NO plaintext.

### 2.3 Protection Against Key Guessing via PBKDF2
- With 600,000 iterations of HMAC-SHA256, computing a single key trial takes ~0.45 seconds on modern CPU cores.
- An attacker attempting 1,000,000 passwords requires over 5 days of single-core compute, effectively neutralizing naive dictionary attacks.

### 2.4 Prevention of Cover Desynchronization
- The system embeds an 8-byte magic header (`MEDSTEG1`) and 4-byte length field within the permuted sequence.
- If an unauthorized party attempts extraction with an incorrect stego-key, they read pseudorandom noise from the wrong indices, immediately failing the magic header validation and aborting without attempting decryption.
