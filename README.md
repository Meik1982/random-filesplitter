# rfs - Random File Splitter (v3.0.0 Post-Quantum & High-Performance Rust Edition) 🛡️

**English** | [Deutsch](README.de.md)

[![CI & Build RFS Binaries](https://github.com/Meik1982/random-filesplitter/actions/workflows/build.yml/badge.svg)](https://github.com/Meik1982/random-filesplitter/actions/workflows/build.yml)
[![License: LGPL v3](https://img.shields.io/badge/License-LGPL_v3-blue.svg)](https://www.gnu.org/licenses/lgpl-3.0)
[![Rust](https://img.shields.io/badge/Rust-2021_Edition-orange.svg)](https://www.rust-lang.org)
[![Post-Quantum Hash](https://img.shields.io/badge/Hash-BLKS--384-brightgreen.svg)](https://github.com/Meik1982/blks)

**rfs** is a high-performance, modular systems tool designed for **physical transport security**, cryptographic partitioning, and bit-exact reconstruction of files and Unix streams.

It is built on the mathematical foundation of **Information-Theoretic Security via One-Time-Pad Chain ($N$-out-of-$N$ XOR)**:
A file is split into $N$ parts ($N \ge 2$), where each individual share is mathematically indistinguishable from thermal noise (**100% Plausible Deniability, Zero Forensic Fingerprint**). The original plaintext can only be reconstructed when **all $N$ shares** are combined. If even a single share is missing, the secret remains mathematically unsolvable.

---

## 🚀 Key Features in v3.0.0 (Rust Rewrite)

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
  * No requirement to know the file size in advance; In-Flight BLKS-384 hashing buffers metadata until stream EOF.
* **Machine-Readable NDJSON Telemetry (`--json`):**
  * Structured JSON events on `stderr` (`progress`, `finished`, `error`) with byte counters, throughput, live ETA, and checksums for automation and agent pipelines.
* **Interactive ANSI Progress Bar (`blkcp`-Style):**
  * Dynamic 24-character terminal progress bar with percentage, formatted byte counters, live transfer rates (MB/s / GB/s), and ETA.
* **Advanced NIST SP 800-22 Entropy Diagnostics:**
  * Two-phase system diagnostics (`rfs --entropy-test`) and file entropy analysis (`rfs -a <file>`) featuring Runs tests, Block Frequency tests ($M=128$), analytical `erfc`, and Wilson-Hilferty Chi² approximation.
* **RFS4 Format with Embedded Filename & 4 KiB Cluster Padding:**
  * The original filename is embedded directly into the stealth footer and information-theoretically encrypted across all $N$ shares ($F_1 = \text{Plain} \oplus F_2 \oplus \dots \oplus F_N$).
  * Every share is padded to a multiple of **4 KiB (4,096 bytes cluster alignment)** with ChaCha20 noise—eliminating file-size correlation attacks on the filesystem level.
  * Optional `--pad-to <SIZE>` inflates shares to an exact target size (e.g., `100M`, `20G`).
* **Anonymous Anti-Forensic Naming (`<token6>.rfs`):**
  * Shares and decoys default to uncorrelated 6-character hex tokens (e.g., `a9f4c2.rfs`, `7c1b3e.rfs`).
  * The filesystem reveals neither the original filename, nor the number of shares, nor which files are real shares and which are decoys.
* **Automatic Restoration:**
  * `rfs restore a9f4c2.rfs 7c1b3e.rfs` extracts the original filename directly from the decrypted footer and restores the file under its true name.
* **100% Backward Compatibility:**
  * Transparently identifies and restores legacy RFS3 and RFS2 archives (60B / 44B footers, SHA-256 / BLKS-384) from previous releases bit-for-bit.
* **Anti-Forensic Decoys & Traffic Obfuscation:**
  * Generate indistinguishable chaff files filled with 100% ChaCha20 random noise (`-d, --decoys` during split or standalone `rfs decoy`).
  * Smart pattern matching: calculates target share size for raw files (`size + 64 bytes footer + padding`) or duplicates existing share sizes 1:1.

---

## 💻 Usage

### 1. Splitting Files (RFS4 N-Way One-Time-Pad)
```bash
# Split into 2 anonymous shares (creates e.g. a9f4c2.rfs, 7c1b3e.rfs with 4 KiB cluster padding)
rfs split data.iso

# Split into 3 shares and pad to an exact size of 50 MB
rfs split -n 3 data.iso --pad-to 50M

# Shuffle with 3 decoy files (generates 6 indistinguishable files with random tokens)
rfs split -n 3 data.iso -d 3

# With memory locking (mlock) and parallel disk fanout across separate mountpoints
rfs split -n 3 --mlock data.iso /media/usb1/pA.rfs /media/usb2/pB.rfs /media/usb3/pC.rfs
```

### 2. Restoring & Verifying Files
```bash
# Automatically restores original filename from the RFS4 footer:
rfs restore a9f4c2.rfs 7c1b3e.rfs

# Restore into a specific target destination (or '-' for stdout)
rfs restore a9f4c2.rfs 7c1b3e.rfs -o custom_name.iso

# Fast integrity verification in RAM without writing to disk
rfs verify a9f4c2.rfs 7c1b3e.rfs
```

### 3. Unix Streaming Pipes
```bash
# Stream tar archive into 4 shares on-the-fly
tar -czf - /var/data | rfs split -n 4 - -o backup

# Restore from 4 shares directly to stdout and decompress
rfs restore backup.rfs1 backup.rfs2 backup.rfs3 backup.rfs4 -o - | tar -xzf -
```

### 4. Decoys & Anti-Forensics
```bash
# Generate 4 decoys during split (total of 7 files)
rfs split -n 3 secret.iso -d 4

# Create decoys matching an existing raw file (+64 bytes footer automatically calculated)
rfs decoy -t contract.pdf -c 5

# Create decoys matching an existing RFS share (exact 1:1 byte size)
rfs decoy -t 7c1b3e.rfs -c 3

# Create decoys with explicit target size (e.g. 50 MB)
rfs decoy -s 50M -c 2 -o fake_share
```

### 5. Machine-Readable Telemetry (--json)
```bash
rfs split -n 3 huge.iso --json
# Emits NDJSON on stderr:
# {"event":"progress","action":"Split","processed_bytes":524288000,"total_bytes":1048576000,"percent":50.00,"speed_bps":1850230120,"elapsed_s":0.28,"eta_s":0.2}
# {"event":"finished","action":"Split","processed_bytes":1048576000,"elapsed_s":0.5512,"avg_speed_bps":1902340123,"num_parts":3,"checksum":{"algorithm":"blks-384","digest":"..."}}
```

### 6. Cryptanalysis & Benchmarks
```bash
# NIST SP 800-22 file entropy analysis
rfs -a data.iso.rfs1

# Two-phase hardware and system entropy diagnostics
rfs --entropy-test

# Hardware throughput benchmark (SIMD ChaCha20, XOR, BLKS-384)
rfs --benchmark
```

---

## 🛠️ Building & Installation

### Requirements
* Rust Toolchain (Edition 2021, MSRV 1.75+)

### Build from Source
```bash
git clone https://github.com/Meik1982/random-filesplitter.git
cd random-filesplitter
cargo build --release

# Test binary
./target/release/rfs --version
./target/release/rfs --benchmark
```

### Arch Linux / CachyOS (makepkg)
```bash
cd packaging/arch
makepkg -si
```

---

## 📊 Cryptanalytic Validation (Plausible Deniability)

Every split share provably satisfies the following statistical thresholds:

| Metric | Target / Ideal | Typical RFS Value | Status |
| :--- | :--- | :--- | :--- |
| **Shannon Entropy** | $\approx 8.000000$ bits/byte | **$7.99983$ bits/byte** | ✅ Passed |
| **Chi-Square ($\chi^2$)** | $180.0 \dots 330.0$ ($p = 0.05 \dots 0.95$) | **$248.32$** | ✅ Passed |
| **Arithmetic Mean** | $127.500$ | **$127.498$** | ✅ Passed |
| **Bit Balance (1/0)** | $50.000\%$ | **$50.016\%$** | ✅ Passed |
| **NIST Runs Test** | $p \ge 0.01$ | **$p = 0.627$** | ✅ Passed |
| **NIST Block Frequency ($M=128$)** | $p \ge 0.01$ | **$p = 0.172$** | ✅ Passed |

---

## 📜 License & Copyright

Copyright (c) 2026 Meik Augenblick.  
Licensed under the **GNU Lesser General Public License v3.0 (LGPL v3)**.
