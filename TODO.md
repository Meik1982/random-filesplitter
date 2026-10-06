# random-filesplitter (rfs): Roadmap, Architektur & Quality Gates

Kryptografisch sicheres Datei-Splitting- und Rekonstruktionswerkzeug mit plausibler Abstreitbarkeit (Plausible Deniability), ChaCha20-CSPRNG, RFS2/RFS3-Stealth-Footer und nativer 384-Bit Post-Quantum BLKS-Integrität.

---

## 🗺️ v3.0.0 Architektur-Evolution: Roadmap in 4 Stufen

### 🔴 Stufe 1: Absolut notwendig (v3.0.0 Meilenstein)
- [ ] **Sprach- & Architekturmigration (C++ ➔ Rust)**
  - Neuschreiben von RFS als modernes, sicheres Rust-Projekt (`cargo`).
  - Native Einbindung von `blks` als Crate (`blks-core`) ohne FFI-Overhead (Zero-Cost Inlining & LTO).
  - Plattformunabhängiges Cross-Compiling (Linux, Windows, macOS) ohne C++-Toolchain-Reibung.
- [ ] **BLKS-384 Integration (Beseitigung des SHA-256 Flaschenhalses)**
  - Ersetzen des langsamen Skalar-SHA-256 (224 MB/s) durch `blks` (6.300 MB/s).
  - Entfesselt die Pipeline auf NVMe- und ChaCha20-Höchstgeschwindigkeit (28-facher Hash-Durchsatz).
  - 192-Bit Post-Quantum Kollisionssicherheit (384-Bit Merkle-Tree Hash).
- [ ] **Neues Format `RFS3` (Post-Quantum Stealth)**
  - 60-Byte ge-XORter Metadaten-Footer: `4B Magic ("RFS3")` + `48B BLKS-384 Digest` + `8B Dateigröße`.
  - 100 % Plausible Deniability (statistisch ununterscheidbar von weißem Rauschen).
- [ ] **100 % Abwärtskompatibilität für `RFS2` (Restore)**
  - Automatische Magic-Erkennung beim Wiederherstellen:
    - `"RFS2"` ➔ SHA-256 Verifikation (historische Splits bleiben lesbar).
    - `"RFS3"` ➔ BLKS-384 Verifikation (High-Speed Standard).
- [ ] **Hardware-Benchmark Korrektur**
  - RAM-zu-RAM XOR-Benchmark auf natives SIMD (AVX2 / NEON) ausrichten, um reellen Durchsatz (15–20 GB/s) anzuzeigen.

---

### 🟡 Stufe 2: Wichtig (High-Priority – Kernarchitektur & Durchsatz)
- [ ] **Entkoppelte Streaming-Pipeline (Zero-Copy Triple-Buffering)**
  - Reader-, Crypto/XOR- und Writer-Threads über lockfreie Ringpuffer / Scoped Channels vollständig entkoppeln.
  - Zero-Allocation während des gesamten Datenstroms.
- [ ] **Fast-Verify Modus (`rfs --verify <teil1> <teil2>`)**
  - Schnelle Integritäts- und Entschlüsselbarkeitsprüfung im RAM **ohne** Schreiben auf die Zielfestplatte.
  - Ideal zur Validierung großer Backups und Archive.
- [ ] **Unix Stdin/Stdout Streaming-Pipes**
  - Direkte Pipe-Unterstützung: `tar -czf - /data | rfs split - teil1.rfs teil2.rfs`
  - Kein temporäres Zwischenspeichern gigantischer Archive mehr erforderlich.

---

### 🟢 Stufe 3: Empfohlen (Power-Features & Ergonomie)
- [ ] **N-Way Splitting (Aufteilung in 3, 4 oder N Teile)**
  - Beliebig viele Teile über One-Time-Pad Chain: $P = C_1 \oplus C_2 \oplus \dots \oplus C_n$.
  - Alle Teile zwingend zur Rekonstruktion erforderlich.
- [ ] **Maschinenlesbare JSON-Telemetrie (`--json`)**
  - Strukturierte NDJSON-Ausgabe auf `stderr` (analog zu `blkcp`) für Skripte, CI/CD und Agenten-Pipelines.
- [ ] **Interaktive Fortschrittsanzeige (`blkcp`-Style)**
  - Prozentualer Balken, dynamische ETA-Kalkulation und Durchsatzanzeige in MB/s via ANSI-Escapes.
- [ ] **Erweiterte NIST SP 800-22 Entropieanalyse**
  - Ausbau des `-a / --analyze` Werkzeugs um Runs-Tests, Block-Frequenztests und Krypto-Audit-Metriken.

---

### 🔵 Stufe 4: Nice to Have (Zukunfts-Vision)
- [ ] **Shamir's Secret Sharing Modus ($K$-aus-$N$ Threshold)**
  - Mathematische Rekonstruktion aus beliebigen $K$ von $N$ Teilen (Kryptografische Oberklasse).
- [ ] **Direct I/O (`O_DIRECT`) auf Linux**
  - Umgehung des OS Page-Caches bei Multi-Gigabyte-Dateien zur Schonung des Systemspeichers.
- [ ] **Paketierung & Systemintegration**
  - Arch Linux / CachyOS PKGBUILD (`rfs` / `rfs-git`).
  - Shell-Completions für Bash, Zsh und Fish sowie vollständige Manpages (`rfs.1`).

---

## ✅ Historie: Abgeschlossene Härtungen (v2.1.0 C++17)

- [x] **Compiler- & Linker-Härtung (Full-RELRO Standard)**
  - Linker: `-pie -Wl,-z,relro,-z,now -Wl,-z,noexecstack` (Full-RELRO, NX Stack).
  - Schutzschilde: `-fstack-protector-strong`, `-fstack-clash-protection`, `-D_FORTIFY_SOURCE=3`.
  - C++17 Upgrade und Clang/GCC Multi-Target CI.
- [x] **Sanitizer-Integration & Zero-Warning Policy**
  - `make asan` (AddressSanitizer) & `make ubsan` (UndefinedBehaviorSanitizer).
  - 0 Warnings unter `-Wall -Wextra` auf Linux, macOS und Windows MinGW.
- [x] **I/O-Pipeline & Zero-Allocation Double-Buffering**
  - Worker mit O(1) Pointer-Swapping (`std::swap`).
  - Vektorisierter AVX2 256-Bit Fast-Path (`_mm256_xor_si256`).
  - Sichere Speicherhygiene (`secure_wipe_memory`).
- [x] **Konfigurierbare Puffergröße (`-B / --block-size`) & Kernel-Readahead (`posix_fadvise`)**
- [x] **Gehärtetes Hybrid-Entropie-Harvesting & VM-Quantisierungskompensation**
