# Mathematical Algorithms: SPHINCS+ / SLH-DSA

## 1. Mathematical Primitives

### 1.1 Hash and Tweakable Hash Functions
All cryptographic operations in `SLH-DSA-SHA2-128f` are built on SHA-256 parameterized with an **Address Structure (ADRS)**:
- $ADRS$ is a 32-byte data structure that encodes the layer number, tree address within the layer, keypair address, hash tree level, and leaf index.
- A tweakable hash function is defined as:
  $$\mathbf{Th}_k(ADRS, M) = \text{SHA-256}(PK.\text{seed} \parallel ADRS \parallel M)$$
- This structure prevents multi-target attacks: an adversary cannot reuse hash evaluations across different nodes or subtrees.

---

## 2. One-Time Signatures: WOTS+ (Winternitz OTS)
WOTS+ signs an $m$-bit message using hash chains of length $w = 16$.
1. **Secret Key**: $len$ strings of $n=16$ bytes derived from $SK.\text{seed}$ using a PRF.
2. **Hash Chaining Function**: For an element $x$ and chain step $s$, the function iteratively hashes:
   $$c^s(x) = \mathbf{Th}(\text{step } s, \dots, c^{s-1}(x))$$
3. **Public Key**: The end of each chain $c^{w-1}(sk_i)$ for $i \in [0, len-1]$.
4. **Signature**: Given message digits $b_0, b_1, \dots \in [0, w-1]$, the signature is:
   $$\sigma_i = c^{b_i}(sk_i)$$
5. **Verification**: Verifier computes $c^{w - 1 - b_i}(\sigma_i)$ and confirms it equals the known public key.

---

## 3. Few-Time Signatures: FORS (Forest of Random Subsets)
1. Message digest is partitioned into $k=33$ indices: $(idx_0, idx_1, \dots, idx_{k-1})$ where each $idx_j \in [0, 2^a - 1]$ and $a=6$.
2. For each tree $j \in [0, 32]$:
   - The secret leaf value at $idx_j$ is revealed.
   - The authentication path of length $a=6$ (hashes of sibling nodes up to the tree root) is included.
3. The roots of all $k=33$ trees are compressed using $\mathbf{Th}$ to yield $PK_{\text{FORS}}$.

---

## 4. Complete Verification Algorithm
1. Parse signature $\Sigma = (R, \sigma_{\text{FORS}}, \sigma_{\text{HT}})$.
2. Compute randomized message hash $m_{\text{hash}} = H_{\text{msg}}(R, PK, M)$.
3. Reconstruct FORS public key:
   $$PK_{\text{FORS}} \leftarrow \text{FORS\_PK\_From\_Sig}(\sigma_{\text{FORS}}, m_{\text{hash}}, PK.\text{seed}, ADRS)$$
4. Initialize current root $node \leftarrow PK_{\text{FORS}}$.
5. For layer $i = 0$ to $d-1$:
   - Verify WOTS+ signature on $node$.
   - Compute XMSS root using the subtree authentication path.
   - Set $node \leftarrow \text{computed subtree root}$.
6. Return `True` if $node == PK.\text{root}$, else `False`.
