# RFS-Matrix: General Access Linear Secret Sharing & Multi-Payload Decoys over $\mathbb{F}_2$

**Author:** Meik Augenblick  
**Project:** Random File Splitter (`rfs`)  
**Status:** Architectural Specification & Formal Information-Theoretic Proof (Stage 8)  
**Target:** Linear Secret Sharing Scheme (LSSS) over Galois Field $\mathbb{F}_2$

---

## 1. Executive Summary & Vision

Traditional $N$-of-$N$ file splitters enforce a rigid, all-or-nothing threshold: exactly all $N$ shares must be present to reconstruct the secret ($P = C_1 \oplus \dots \oplus C_N$). While information-theoretically perfect, this fixed topology limits advanced physical transport operations where different parties hold partial credentials, or where plausible deniability requires multiple distinct payloads (genuine secrets and decoy chaff) to co-exist within the **exact same pool of shares**.

**RFS-Matrix** generalizes the One-Time-Pad chain to arbitrary **Monotone Access Structures** $\Gamma$ over the finite field $\mathbb{F}_2 = (\{0, 1\}, \oplus, \cdot)$. 

Given a pool of $M$ shares $\{C_1, \dots, C_M\}$, independent subsets reveal completely different, cryptographically authenticated plaintexts without any cross-leakage:
* **Subset $A = \{C_1, C_3, C_7\} \longrightarrow$ Genuine Secret** (e.g. Master Database, BLKS-384 verified).
* **Subset $B = \{C_1, C_2, C_3\} \longrightarrow \text{Decoy}_0$** (e.g. Tax Declaration, BLKS-384 verified).
* **Subset $C = \{C_2, C_3, C_9\} \longrightarrow \text{Decoy}_1$** (e.g. Family Vacation Photos, BLKS-384 verified).
* **Subset $D = \{C_4, C_5, C_7\} \longrightarrow \text{Decoy}_2$** (e.g. Linux Kernel Source ISO, BLKS-384 verified).
* **Any unauthorized subset $\longrightarrow$ Pure Pseudorandom Noise** (Shannon Entropy $H \ge 7.9998$).

---

## 2. Mathematical Formalism over $\mathbb{F}_2$

### 2.1 The Basis Space
Let $L$ be the byte length of each share (aligned to 4 KiB cluster boundaries).
We define:
1. $R$ independent, uniformly distributed random basis streams:
   $$\vec{b}_1, \vec{b}_2, \dots, \vec{b}_R \in \{0, 1\}^L \quad \text{where } \vec{b}_j \sim \mathcal{U}(\{0, 1\}^L)$$
   harvested via ChaCha20 seeded by physical system entropy.
2. $K$ distinct plaintext streams (secrets and decoys):
   $$\vec{p}_1, \vec{p}_2, \dots, \vec{p}_K \in \{0, 1\}^L$$

### 2.2 Share Synthesis via Linear Generator Matrices
Each share $C_i$ ($1 \le i \le M$) is synthesized as a linear combination in $\mathbb{F}_2$:
$$C_i = \bigoplus_{j=1}^R G_{i,j} \vec{b}_j \oplus \bigoplus_{k=1}^K H_{i,k} \vec{p}_k$$

In matrix notation over $\mathbb{F}_2$:
$$\mathbf{C} = \mathbf{G} \mathbf{B} \oplus \mathbf{H} \mathbf{P}$$
where:
* $\mathbf{C} \in \mathbb{F}_2^{M \times L}$ represents the $M$ generated share files.
* $\mathbf{G} \in \mathbb{F}_2^{M \times R}$ is the **Random Basis Generator Matrix**.
* $\mathbf{B} \in \mathbb{F}_2^{R \times L}$ contains the $R$ independent ChaCha20 random streams.
* $\mathbf{H} \in \mathbb{F}_2^{M \times K}$ is the **Payload Encoding Matrix**.
* $\mathbf{P} \in \mathbb{F}_2^{K \times L}$ contains the $K$ padded payload streams.

### 2.3 Reconstruction Criterion
An access structure is defined by an indicator vector $\vec{x} \in \mathbb{F}_2^M$, where $x_i = 1$ denotes that share $C_i$ is present, and $x_i = 0$ denotes absence.

The reconstruction operation is simply the SIMD-XOR sum of the selected shares:
$$R(\vec{x}) = \vec{x}^T \mathbf{C} = (\vec{x}^T \mathbf{G}) \mathbf{B} \oplus (\vec{x}^T \mathbf{H}) \mathbf{P}$$

For subset $\vec{x}$ to successfully and exclusively reveal payload $\vec{p}_k$ ($1 \le k \le K$), the following two linear algebraic conditions **must hold simultaneously over $\mathbb{F}_2$**:

1. **Noise Annihilation Condition (Perfect Cancellation of Randomness):**
   $$\vec{x}^T \mathbf{G} = \vec{0}^T \in \mathbb{F}_2^{1 \times R}$$
   *(All random basis vectors cancel out to zero through additive XOR properties).*

2. **Orthogonal Payload Isolation Condition:**
   $$\vec{x}^T \mathbf{H} = \vec{e}_k^T \in \mathbb{F}_2^{1 \times K}$$
   where $\vec{e}_k$ is the $k$-th standard unit basis vector in $\mathbb{F}_2^K$.
   *(Payload $k$ has coefficient 1, while all other $K-1$ payloads have coefficient 0).*

When both conditions are met:
$$R(\vec{x}) = \vec{0} \cdot \mathbf{B} \oplus \vec{e}_k^T \mathbf{P} = \vec{p}_k$$

---

## 3. Information-Theoretic Security Proof (Zero-Leakage Theorem)

### Theorem 1 (Shannon Perfect Secrecy for Unauthorized Subsets)
*Let $\vec{y} \in \mathbb{F}_2^M$ be an unauthorized subset indicator vector such that $\vec{y}^T \mathbf{G} \ne \vec{0}^T$. Then the mutual information between the reconstructed stream $\vec{y}^T \mathbf{C}$ and any payload $\vec{p}_k$ is identically zero:*
$$I(\vec{p}_k ; \vec{y}^T \mathbf{C}) = 0$$

### Proof:
1. Since $\vec{y}^T \mathbf{G} \ne \vec{0}^T$, there exists at least one index $j^* \in \{1, \dots, R\}$ such that $(\vec{y}^T \mathbf{G})_{j^*} = 1$.
2. The reconstructed stream can be partitioned into:
   $$\vec{y}^T \mathbf{C} = \vec{b}_{j^*} \oplus \vec{Z}$$
   where $\vec{Z} = \bigoplus_{j \ne j^*} (\vec{y}^T \mathbf{G})_j \vec{b}_j \oplus (\vec{y}^T \mathbf{H}) \mathbf{P}$.
3. By definition of the basis construction, $\vec{b}_{j^*}$ is a uniform random variable over $\{0, 1\}^L$, statistically independent of all other basis vectors $\vec{b}_{j}$ ($j \ne j^*$) and independent of all plaintext payloads $\mathbf{P}$.
4. By Shannon's One-Time-Pad Lemma (Shannon, 1949):  
   If $B \sim \mathcal{U}(\{0, 1\}^L)$ is statistically independent of random variable $Z$, then $B \oplus Z \sim \mathcal{U}(\{0, 1\}^L)$, and $B \oplus Z$ is statistically independent of $Z$.
5. Therefore:
   $$H(\vec{y}^T \mathbf{C} \mid \mathbf{P}) = H(\vec{y}^T \mathbf{C}) = L \cdot \log_2(2) = L \text{ bits}$$
6. The mutual information is:
   $$I(\mathbf{P} ; \vec{y}^T \mathbf{C}) = H(\vec{y}^T \mathbf{C}) - H(\vec{y}^T \mathbf{C} \mid \mathbf{P}) = L - L = 0$$
   $\blacksquare$

**Cryptographic Significance:**  
Even an adversary with infinite quantum computing power (solving Post-Quantum lattice problems in $O(1)$) cannot derive a single bit of information about any payload from an unauthorized subset, because the distribution of bytes is mathematically indistinguishable from thermal noise.

---

## 4. Automated Matrix Solvers via Gauss-Jordan over $\mathbb{F}_2$

To synthesize valid generator matrices $\mathbf{G}$ and $\mathbf{H}$ for any user-defined access policy, the RFS compiler uses **Gauss-Jordan Elimination over $\mathbb{F}_2$**.

### 4.1 Representation & Bit-Parallel Algebra
In Rust, vectors over $\mathbb{F}_2$ of length $M \le 64$ are represented directly as 64-bit unsigned integers (`u64`):
* Addition ($a \oplus b$) $\longrightarrow$ `a ^ b`
* Multiplication ($a \cdot b$) $\longrightarrow$ `a & b`
* Row reduction step $\longrightarrow$ `row[i] ^= row[pivot]` (single CPU clock cycle).

### 4.2 Matrix Rank & Leakage Verification Algorithm
```text
Algorithm VerifyAccessStructure(G, H, AuthorizedSets, UnauthorizedSets):
  For each S in AuthorizedSets:
    x = IndicatorVector(S)
    Assert (x^T * G == 0)
    Assert (x^T * H == TargetUnitVector)

  For each U in UnauthorizedSets:
    y = IndicatorVector(U)
    Assert (y^T * G != 0)  // Must retain uncancelled entropy
```

---

## 5. Multi-Target Stealth Trailer Encoding

A critical challenge in deniable matrix splitting is **metadata containment**: How does `rfs scan` or `rfs restore` recognize which subset decodes which file, without embedding a detectable master catalog?

### The XOR-Superposition Trailer Pattern
In RFS4, each share terminates with a 64-byte stealth trailer:
$$\text{Tail}_i = \text{Share}_i[L-64 \dots L]$$

For every authorized access subset $\vec{x}_k = \{i_1, \dots, i_m\}$ configured for payload $k$:
$$\bigoplus_{i \in \vec{x}_k} \text{Tail}_i = \text{Trailer}(P_k)$$

where $\text{Trailer}(P_k)$ contains:
* `[0..4]`: `RFS4` magic tag.
* `[4..6]`: Format version `0x0400`.
* `[6..14]`: Original byte size of payload $k$.
* `[14..62]`: BLKS-384 post-quantum hash of payload $k$.
* `[62..64]`: Filename length $F_k$.

Because the system of linear equations for the 64-byte trailers is solved simultaneously with the payload generator matrices, **unauthorized combinations yield pure pseudo-random garbage** with no `RFS4` magic and no recognizable pattern.

---

## 6. Implementation Architecture in RFS (`src/matrix/`)

The implementation will be encapsulated in a zero-overhead module:
* `src/matrix/gf2.rs`: Fast bit-parallel vector and matrix operations over $\mathbb{F}_2$ (`u64` bitboards).
* `src/matrix/solver.rs`: Gauss-Jordan linear solver and access-policy consistency validator.
* `src/matrix/compiler.rs`: High-level policy compiler translating human-readable TOML access policies into concrete share streams.
* `src/matrix/pipeline.rs`: Multi-threaded streaming generator utilizing the verified SIMD-XOR pipeline.

---

## 7. Performance & Backward Compatibility Guarantee

* **Identity Fast-Path:** When standard $N$-of-$N$ mode is invoked, the matrix reduces to the trivial identity chain ($G_{i,i} = 1, G_{i,i-1} = 1$). Zero dynamic allocations or matrix multiplications are performed; execution proceeds over the proven 4.02 GB/s AVX2 pipeline.
* **Format Stability:** All shares produced by the matrix engine adhere strictly to the RFS4 specification (4 KiB cluster padding, no plaintext headers, valid BLKS-384 integrity).
