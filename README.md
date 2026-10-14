# rfs - Random File Splitter (v3.1.0 Post-Quantum & High-Performance Rust Edition) 🛡️

**English** | [Deutsch](README.de.md)

[![CI & Build RFS Binaries](https://github.com/Meik1982/random-filesplitter/actions/workflows/build.yml/badge.svg)](https://github.com/Meik1982/random-filesplitter/actions/workflows/build.yml)
[![License: LGPL v3](https://img.shields.io/badge/License-LGPL_v3-blue.svg)](https://www.gnu.org/licenses/lgpl-3.0)
[![Rust](https://img.shields.io/badge/Rust-2021_Edition-orange.svg)](https://www.rust-lang.org)
[![Post-Quantum Hash](https://img.shields.io/badge/Hash-BLKS--384-brightgreen.svg)](https://github.com/Meik1982/blks)

**rfs** is a high-performance, modular systems tool designed for **physical transport security**, cryptographic partitioning, and bit-exact reconstruction of files and Unix streams.

It is built on the mathematical foundation of **Information-Theoretic Security via One-Time-Pad Chain ($N$-out-of-$N$ XOR)** and **General Access Linear Secret Sharing over $\mathbb{F}_2$**:
A file is split into $N$ parts ($N \ge 2$), where each individual share is mathematically indistinguishable from thermal noise (**100% Plausible Deniability, Zero Forensic Fingerprint**). The original plaintext can only be reconstructed when **all $N$ shares** are combined. If even a single share is missing, the secret remains mathematically unsolvable.

---

## 🚀 Key Features in v3.1.0

* **Combinatorial Auto-Discovery & Assembly Engine (`rfs scan`):**
  * Reads only the 64-byte trailers in RAM without scanning multi-gigabyte payloads.
  * Discovers all valid $N$-way OTP sets from arbitrary folders in milliseconds and automatically distinguishes genuine shares from decoy chaff.
  * **1-Click Auto-Restore:** `rfs scan *.rfs -r -o ./recovered` automatically reconstructs all discovered payloads bit-for-bit.
* **Deniable Decoy Forge (`rfs forge` / Rubber-Hose Defense):**
  * Mathematically exploits OTP information-theoretic security: Given $K$ seized shares and a harmless decoy file (e.g. vacation photos or a dummy PDF), `rfs forge` synthesizes a tailored counterpart share.
  * Combining the seized shares with the fake counterpart restores the decoy file with **100% BLKS-384 PQ integrity** (green status). An adversary cannot mathematically prove another original existed.
* **Simultaneous Multi-Payload Decoys (`rfs split --decoy-reveal <FILE>`):**
  * Embeds an authentic plaintext decoy directly during the initial split.
  * Real shares reconstruct the true secret; the decoy counterpart reconstructs the harmless decoy file.
* **Modern Slint Desktop GUI (`rfs-gui`):**
  * Native, GPU-accelerated desktop interface with 3 tabs: `📦 Aufteilen (Split)`, `🔓 Wiederherstellen & Scanner (Restore)`, and `🎭 Täuschung (Forge)`.
  * Shipped with custom crystal app icon and `.desktop` Linux desktop integration.
* **Post-Quantum Stealth Footer (RFS4):**
  * Employs **BLKS-384** (384-bit Post-Quantum Merkle-Tree Hashing) instead of legacy SHA-256, eliminating hashing bottlenecks (**3.3x faster than SHA-256**).
  * The 64-byte stealth metadata trailer is $N$-way XOR-encrypted across all shares. In isolation, every share is 100% high-entropy noise with zero plaintext headers or magic numbers.
  * Instant sub-millisecond abort (< 1 ms) upon detecting tampered, corrupt, or mismatched shares.
* **$N$-Way One-Time-Pad Splitting (2 to 64 Shares):**
  * Arbitrary partitioning into 3, 4, or $N$ shares via `-n, --parts <COUNT>`.
  * Shares $2 \dots N$ are filled with uncorrelated ChaCha20-CSPRNG keystreams; Share 1 closes the loop with SIMD-accelerated XOR ($P = C_1 \oplus C_2 \oplus \dots \oplus C_N$).
* **Decoupled 3-Stage Pipeline & Parallel Disk Fanout:**
  * Dedicated worker threads for Reader, SIMD/Crypto engine, and Writer, synchronized over bounded channels (`crossbeam-channel` with zero-allocation triple-buffering).
  * True concurrent I/O fanout across independent physical mountpoints (e.g., separate USB flash drives or NVMe disks).
  * Saturated memory bus speeds: up to **1.85 GB/s ChaCha20** and **~4.0 GB/s SIMD-XOR**.
* **Swap Resilience via Memory-Locking (`--mlock`):**
  * Locks cryptographic and I/O buffer pools into physical RAM via POSIX `mlock` to prevent sensitive plaintext or keystreams from being swapped to disk or hibernation files.
* **Unix Streaming Pipes (POSIX `-` Support):**
  * Native integration into Unix pipelines: reads from `stdin` and emits to `stdout`.
* **Machine-Readable NDJSON Telemetry (`--json`):**
  * Structured JSON events on `stderr` (`progress`, `finished`, `error`) with byte counters, throughput, live ETA, and checksums for automation and agent pipelines.
* **Interactive ANSI Progress Bar:**
  * Dynamic terminal progress bar with percentage, formatted byte counters, live transfer rates (MB/s / GB/s), and ETA.
* **Advanced NIST SP 800-22 Entropy Diagnostics:**
  * Two-phase system diagnostics (`rfs --entropy-test`) and file entropy analysis (`rfs -a <file>`) featuring Runs tests, Block Frequency tests ($M=128$), analytical `erfc`, and Wilson-Hilferty Chi² approximation.
* **RFS4 Format with Embedded Filename & 4 KiB Cluster Padding:**
  * The original filename is embedded directly into the stealth footer and information-theoretically encrypted across all $N$ shares.
  * Every share is padded to a multiple of **4 KiB (4,096 bytes cluster alignment)** with ChaCha20 noise—eliminating file-size correlation attacks on the filesystem level.
  * Optional `--pad-to <SIZE>` inflates shares to an exact target size (e.g., `100M`, `20G`).
* **Anonymous Anti-Forensic Naming (`<token6>.rfs`):**
  * Shares and decoys default to uncorrelated 6-character hex tokens (e.g., `a9f4c2.rfs`, `7c1b3e.rfs`).
* **100% Backward Compatibility:**
  * Transparently identifies and restores legacy RFS3 and RFS2 archives (60B / 44B footers, SHA-256 / BLKS-384) from previous releases bit-for-bit.

---

## 💻 Usage

### 1. Splitting Files (RFS4 N-Way One-Time-Pad)
```bash
# Split into 2 anonymous shares (creates e.g. a9f4c2.rfs, 7c1b3e.rfs with 4 KiB cluster padding)
rfs split data.iso

# Split into 3 shares and pad to an exact size of 50 MB
rfs split -n 3 data.iso --pad-to 50M

# Split into 3 shares with an authentic plaintext decoy (simultaneous decoy reveal)
rfs split -n 3 confidential.kdbx --decoy-reveal harmless_recipe.txt -o /media/backup/

# Shuffle with 3 decoy files (generates 6 indistinguishable files with random tokens)
rfs split -n 3 data.iso -d 3
```

### 2. Auto-Discovery & Assembly (`rfs scan`)
```bash
# Inspect all .rfs files in a directory and print discovered sets in milliseconds
rfs scan /media/usb/*.rfs

# Scan and automatically reconstruct all discovered valid sets to a target folder
rfs scan /media/usb/*.rfs -r -o ./restored/
```

### 3. Plausible Deniability Decoy Forge (`rfs forge`)
```bash
# Seized share 'share1.rfs' + harmless decoy 'vacation.pdf' -> generates 'fake_share2.rfs'
rfs forge share1.rfs --reveal-as vacation.pdf -o fake_share2.rfs

# Restoring with the forged share bit-exactly reconstructs vacation.pdf with verified BLKS-384 integrity:
rfs restore share1.rfs fake_share2.rfs
```

### 4. Unix Streaming Pipes
```bash
# Stream stdin directly into 4 shares on disk
tar -czf - /data | rfs split -n 4 - -o backup

# Reconstruct stream directly to stdout without intermediate temporary files
rfs restore backup.*.rfs -o - | tar -xzf -
```

### 5. Integrity Verification (Zero Disk Writes)
```bash
# Verify BLKS-384 Post-Quantum integrity in RAM
rfs verify share1.rfs share2.rfs share3.rfs
```

### 6. Desktop GUI
```bash
# Launch the native Slint GUI
rfs-gui
```

---

## 🏗️ Architecture & Mathematical Foundation

For in-depth mathematical proofs and design specifications, refer to:
* **[docs/lsss-matrix-konzept.md](docs/lsss-matrix-konzept.md):** Information-Theoretic Security Proof (Shannon Perfect Secrecy $I(\mathbf{P}; \vec{y}^T \mathbf{C}) = 0$) & Bit-Parallel $\mathbb{F}_2$ Linear Secret Sharing.
* **[docs/articles/zero-allocation-pipeline-rust.md](docs/articles/zero-allocation-pipeline-rust.md):** Architectural deep dive into the SIMD-accelerated zero-allocation streaming pipeline.

---

## 📜 License

Copyright (c) 2026 Meik Augenblick.  
Licensed under the **GNU Lesser General Public License v3.0 or later (LGPL v3)**.
