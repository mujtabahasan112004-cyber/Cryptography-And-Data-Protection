# Cryptographic Algorithm Specifications: ChaCha20 & CSPRNG Operations

## 1. ChaCha20 Stream Cipher
ChaCha20 is an evolution of the Salsa20 stream cipher developed by Daniel J. Bernstein. It operates on 32-bit unsigned integers arranged in a $4 \times 4$ matrix.

### 1.1 State Representation
The 512-bit (64-byte) internal block state is configured as follows:

| Index | Type | Value / Purpose |
|---|---|---|
| 0 | Constant | `0x61707865` ("expa") |
| 1 | Constant | `0x3320646e` ("nd 3") |
| 2 | Constant | `0x79622d32` ("2-by") |
| 3 | Constant | `0x6b206574` ("te k") |
| 4..11 | Secret Key | 256-bit symmetric key (8 words of 32 bits each) |
| 12..13 | Block Counter | 64-bit integer tracking block sequence |
| 14..15 | Nonce | 64-bit or 96-bit/128-bit unique initial vector |

### 1.2 The Quarter-Round (QR) Primitive
The fundamental non-linear primitive of ChaCha20 is the Quarter-Round operation acting on four 32-bit words $(a, b, c, d)$:

```
a += b;  d ^= a;  d <<<= 16;
c += d;  b ^= c;  b <<<= 12;
a += b;  d ^= a;  d <<<= 8;
c += d;  b ^= c;  b <<<= 7;
```

Where:
- `+=` denotes addition modulo $2^{32}$.
- `^=` denotes bitwise XOR ($\oplus$).
- `<<<= n` denotes bitwise circular rotation to the left by $n$ bits.

### 1.3 The 20 Rounds Structure
A complete ChaCha20 block evaluation performs 10 double-rounds (totaling 20 rounds):
- **Column Rounds** (odd rounds):
  - `QR(0, 4, 8, 12)`
  - `QR(1, 5, 9, 13)`
  - `QR(2, 6, 10, 14)`
  - `QR(3, 7, 11, 15)`
- **Diagonal Rounds** (even rounds):
  - `QR(0, 5, 10, 15)`
  - `QR(1, 6, 11, 12)`
  - `QR(2, 7, 8, 13)`
  - `QR(3, 4, 9, 14)`

After round 20, the final state is added word-wise to the initial state to prevent reversing the transformation:
$$\text{OutputBlock}[i] = (\text{State}_{20}[i] + \text{State}_{0}[i]) \pmod{2^{32}}$$

---

## 2. Rejection Sampling for Unbiased Integers

### 2.1 The Modulo Bias Problem
When mapping random bits to an arbitrary integer range $[0, R-1]$, common naive code computes:
$$\text{output} = \text{random\_32bit\_word} \pmod R$$
If $2^{32}$ is not an exact integer multiple of $R$, remainder values below $(2^{32} \pmod R)$ occur $( \lfloor 2^{32} / R \rfloor + 1 )$ times, while larger values occur only $\lfloor 2^{32} / R \rfloor$ times. For example, if $R = 3$ and max random number is 7 ($[0..7]$):
- 0: `0 % 3 = 0`, `3 % 3 = 0`, `6 % 3 = 0` (3 occurrences)
- 1: `1 % 3 = 1`, `4 % 3 = 1`, `7 % 3 = 1` (3 occurrences)
- 2: `2 % 3 = 2`, `5 % 3 = 2` (ONLY 2 occurrences!)
Probability of 0 or 1 is $3/8 = 37.5\%$, whereas probability of 2 is only $2/8 = 25\%$. In gambling, cryptographic key selection, or voting systems, this bias is unacceptable.

### 2.2 Rejection Sampling Solution
1. Let $R = (\text{max\_val} - \text{min\_val}) + 1$.
2. Determine required bytes: $k = \lceil \log_{256}(R) \rceil$.
3. Compute total candidate domain: $M = 256^k$.
4. Compute maximum unbiased threshold:
   $$L = M - (M \pmod R)$$
5. Repeatedly sample $k$ bytes as integer $V \in [0, M-1]$.
6. If $V < L$, accept and return $\text{min\_val} + (V \pmod R)$.
7. If $V \ge L$, reject and resample.
Because $L$ is an exact multiple of $R$, each remainder $0, 1, \dots, R-1$ occurs exactly $L / R$ times. Thus, the distribution is strictly uniform:
$$P(X = x) = \frac{1}{R}, \quad \forall x \in [\text{min\_val}, \text{max\_val}]$$
