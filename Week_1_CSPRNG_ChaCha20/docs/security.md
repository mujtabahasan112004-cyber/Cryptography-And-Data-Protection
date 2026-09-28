# Security Analysis & Threat Model: ChaCha20 CSPRNG

## 1. Threat Model & Adversarial Capabilities
In our security evaluation, we consider an active adversary $\mathcal{A}$ with the following capabilities:
1. **Passive Keystream Observation**: $\mathcal{A}$ can observe large volumes of generated random bytes, integers, and session tokens.
2. **State Compromise at Time $T$**: $\mathcal{A}$ temporarily gains read access to application memory at time $T$.
3. **Entropy Manipulation**: $\mathcal{A}$ may attempt to inject malicious or predictable seed data into the reseed interface.

---

## 2. Security Guarantees & Mitigations

### 2.1 Next-Bit Unpredictability
- **Guarantee**: Given an arbitrary prefix of the keystream $b_1, b_2, \dots, b_k$, no polynomial-time adversary can predict bit $b_{k+1}$ with probability $\frac{1}{2} + \epsilon$ where $\epsilon$ is non-negligible.
- **Mechanism**: The 20 rounds of ARX operations create complete avalanche effect and diffusion. Inverting the output to deduce the 256-bit key requires $2^{256}$ operations, which exceeds the thermodynamic limits of computation.

### 2.2 Forward Secrecy (Backtracking Resistance)
- **Vulnerability**: If an ordinary PRNG state is leaked at time $T$, the attacker can step backward and decrypt all communications or tokens issued before time $T$.
- **Mitigation**: The ChaCha20 CSPRNG implements periodic state ratcheting. Keystream bytes are extracted to form a completely new 256-bit key and 128-bit nonce, and the previous state is discarded. Because ChaCha20 is a one-way permutation, finding previous states from the current state is computationally infeasible.

### 2.3 Defense Against Weak Seed Injection
- **Vulnerability**: If an attacker can inject predictable user entropy (e.g. `reseed(b"known_string")`), they might try to force the generator into a predictable state.
- **Mitigation**: The `reseed()` method **never** replaces the state solely with user input. Instead, it unconditionally draws 32 bytes of fresh kernel entropy from `os.urandom` and hashes the kernel entropy, existing key, and user input together with SHA-256:
  $$\text{Key}_{\text{new}} = \text{SHA-256}(\text{OS\_Entropy} \parallel \text{Key}_{\text{old}} \parallel \text{User\_Entropy})$$
  Because the OS kernel entropy has full entropy, the resulting key always maintains $\ge 256$ bits of entropy regardless of user input.

### 2.4 Why Statistical Tests Do Not Prove Security
Many developers mistakenly assume that passing statistical test suites (such as Dieharder or NIST SP 800-22) proves cryptographic security.
- **Counterexample**: The digits of $\pi$ pass all statistical randomness tests for frequency, runs, and serial correlation. However, any party knowing the index can compute future digits instantly.
- **Counterexample 2**: The Mersenne Twister MT19937 has a period of $2^{19937}-1$ and passes standard statistical tests, but it is 100% reversible after observing 624 outputs.
- **Conclusion**: Statistical tests verify the **absence of obvious distribution defects**; cryptographic security requires **computational one-wayness**.
