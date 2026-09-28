# Security Analysis & Quantum Resilience: SPHINCS+ / SLH-DSA

## 1. Threat Model & Post-Quantum Environment
We assume an active quantum adversary $\mathcal{Q}$ possessing:
1. **Classical Supercomputing Capabilities**: Exaflop-scale computing clusters.
2. **Cryptanalytically Relevant Quantum Computer (CRQC)**: A fault-tolerant quantum computer running thousands of error-corrected logical qubits capable of executing Shor's and Grover's algorithms.

---

## 2. Quantum Resistance Evaluation

### 2.1 Ineffectiveness of Shor's Algorithm
Shor's algorithm exploits the hidden subgroup problem over finite Abelian groups:
- RSA relies on the multiplicative group of integers modulo $N = pq$.
- ECC relies on cyclic groups over elliptic curves: $Q = kP$.
- Both problems exhibit periodicity, allowing the Quantum Fourier Transform (QFT) to compute periods in polynomial time $\mathcal{O}((\log N)^3)$.
- **Why SPHINCS+ is Immune**: SPHINCS+ does not use groups, rings, lattices, or modular arithmetic. It is built strictly from non-algebraic hash function evaluations. There is no periodic mathematical structure for Shor's algorithm or the Quantum Fourier Transform to exploit.

### 2.2 Resistance to Grover's Algorithm
Grover's algorithm searches an unsorted database of size $N$ in $\mathcal{O}(\sqrt{N})$ quantum steps:
- Finding a preimage for an $n$-bit hash takes $\mathcal{O}(2^{n/2})$ quantum queries.
- For `SLH-DSA-SHA2-128f`, the security parameter is $n = 16$ bytes (128 bits). The internal hash function uses SHA-256 (256 bits).
- Preimage resistance against Grover on SHA-256 requires $2^{256/2} = 2^{128}$ quantum operations, satisfying NIST Security Level 1 (matching the classical difficulty of searching a 128-bit key space).

### 2.3 Mitigation of Stateful Rollback Attacks
- In stateful schemes (XMSS / LMS), using a key twice compromises the one-time signature chain.
- In SPHINCS+, the leaf index is selected as a pseudo-random function of the message, public key, and secret PRF key:
  $$\text{index} = \text{PRF}(SK.\text{prf}, \text{OptRand}, M) \pmod{2^h}$$
- Signing the exact same message twice generates identical signatures; signing different messages selects independently random leaves across a space of $2^{66}$ leaves. The chance of birthday collisions is negligible ($< 2^{-128}$).
