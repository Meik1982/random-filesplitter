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
- [x] **Erweiterte Testsuite & Quality Gates**
  - Multi-Chunk Pipeline-Test mit 5 MB Testdaten.
  - Bit-Flip & Tamper Detection Test (erzwingt SHA-256 Integritätsprüfung und Abbruch).
  - Alle Tests laufen unter ASan und UBSan fehlerfrei durch (100% grün).

---

## 🔮 Zukünftige Erweiterungen (Backlog)

- [ ] Direkte Linux AIO / io_uring Integration für Direct-I/O
- [ ] Mehrteiliges Splitten in N Teile (Shamir's Secret Sharing oder N-Way XOR)
- [ ] Autovervollständigungsskripte für Bash, Zsh und Fish
