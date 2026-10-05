# random-filesplitter (rfs): Roadmap, Härtung & Quality Gates

Kryptografisch sicheres Datei-Splitting- und Rekonstruktionswerkzeug mit plausibler Abstreitbarkeit (Plausible Deniability), ChaCha20-CSPRNG und RFS2-Stealth-Footer.

---

## ✅ Abgeschlossene Härtungen & Optimierungen (v2.1.0)

- [x] **Compiler- & Linker-Härtung (Full-RELRO Standard)**
  - Linker-Härtung: `-pie -Wl,-z,relro,-z,now -Wl,-z,noexecstack` (Full-RELRO, NX Stack).
  - Stack-Schutz: `-fstack-protector-strong` und `-fstack-clash-protection`.
  - Quellcode-Schutz: `-D_FORTIFY_SOURCE=3` und `-fPIE`.
  - C++17 Standard-Upgrade (`-std=c++17`).
- [x] **Sanitizer-Integration im Makefile**
  - `make asan`: Automatisierter Testsuite-Durchlauf mit AddressSanitizer (`-fsanitize=address,undefined`).
  - `make ubsan`: Automatisierter Testsuite-Durchlauf mit UndefinedBehaviorSanitizer (`-fsanitize=undefined`).
  - `make release`: Optimierter Build mit `-O3 -flto` und gestrippten Binaries.
- [x] **I/O-Pipeline & Zero-Allocation Double-Buffering**
  - `SplitPipelineWorker` und `RestorePipelineWorker` auf O(1) Zero-Copy Pointer-Swapping (`std::swap`) umgestellt (beseitigt 3 Vektor-Allokationen und Deep-Copies pro Block).
  - Vektorisierter 256-Bit AVX2-XOR Fast-Path (`_mm256_xor_si256`) mit 64-Bit Fallback und Byte-Alignment.
  - Sichere Speicherlöschung (`secure_wipe_memory`) aller Worker-Arbeitspuffer bei Beendigung.
- [x] **Konfigurierbare Puffergröße (`-B / --block-size`) analog zu `blkcp`**
  - CLI-Option mit Suffix-Parser (`K`, `M`, `G` für z.B. `64K`, `1M`, `4M`, `16M`, `64M`).
  - Standardwert: 4 MiB; Grenzbereich: 64 KiB bis 256 MiB.
- [x] **Plattform-optimierte Kernel-I/O (`posix_fadvise`)**
  - `SequentialInputStream` mit `posix_fadvise(POSIX_FADV_SEQUENTIAL)` auf Linux/glibc via `__gnu_cxx::stdio_filebuf`.
  - Portabler Fallback auf Standard C++ `ifstream` auf anderen Plattformen.
- [x] **Gehärtetes Hybrid-Entropie-Harvesting**
  - Primärquelle: OS Kernel-CSPRNG (`getrandom(2)` auf Linux mit Fallback auf `/dev/urandom`, `BCryptGenRandom` auf Windows).
  - Defence-in-Depth: Zusätzliches Einmischen von High-Res-Clocks, ASLR-Pointer-Layout und CPU-Cache-Jitter in den SHA-256-Mixer.
- [x] **Erweiterte Testsuite & Quality Gates**
  - Multi-Chunk Pipeline-Test mit 5 MB Testdaten.
  - Variable Blockgrößen & Suffix-Parser-Test (64 KiB bis 256 MiB).
  - Bit-Flip & Tamper Detection Test (erzwingt SHA-256 Integritätsprüfung und Abbruch).
  - Entropie-Frische- und Nicht-Trivialitäts-Test.
  - Alle Tests laufen unter ASan und UBSan fehlerfrei durch (100% grün).

---

## 🔮 Zukünftige Erweiterungen (Backlog)

- [ ] Mehrteiliges Splitten in N Teile (z.B. k-aus-n Secret Sharing oder kaskadiertes N-Way XOR)
- [ ] Direkte Linux AIO / io_uring Integration für Direct-I/O
- [ ] Autovervollständigungsskripte für Bash, Zsh und Fish
