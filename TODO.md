# random-filesplitter (rfs): Roadmap, Architektur & Quality Gates

Kryptografisch sicheres Datei-Splitting- und Rekonstruktionswerkzeug mit plausibler Abstreitbarkeit (Plausible Deniability), ChaCha20-CSPRNG, RFS2/RFS3-Stealth-Footer und nativer 384-Bit Post-Quantum BLKS-Integrität.

---

## 🗺️ v3.0.0 Architektur-Evolution: Roadmap in 4 Stufen

### 🔴 Stufe 1: Absolut notwendig (v3.0.0 Meilenstein) – ✅ ABGESCHLOSSEN
- [x] **Sprach- & Architekturmigration (C++ ➔ Rust)**
  - Neuschreiben von RFS als modernes, sicheres Rust-Projekt (`cargo`, Edition 2021).
  - Native Einbindung von `blks` als Crate (`blks-core`) ohne FFI-Overhead (Zero-Cost Inlining & LTO).
  - Multi-Plattform GitHub Actions CI (Linux `x86_64`, macOS `arm64`, Windows `x86_64` MSVC) zu **100 % grün**.
- [x] **BLKS-384 Integration (Beseitigung des SHA-256 Flaschenhalses)**
  - Ersetzen des langsamen Skalar-SHA-256 (224 MB/s) durch `blks` (751 MB/s im Single-Stream bis 6,3 GB/s parallel).
  - ChaCha20 Durchsatz auf **1,88 GB/s** gesteigert (+62 % schneller als C++).
  - 192-Bit Post-Quantum Kollisionssicherheit (384-Bit Merkle-Tree Hash).
- [x] **Neues Format `RFS3` (Post-Quantum Stealth)**
  - 60-Byte ge-XORter Metadaten-Footer: `4B Magic ("RFS3")` + `48B BLKS-384 Digest` + `8B Dateigröße`.
  - 100 % Plausible Deniability (statistisch ununterscheidbar von weißem Rauschen).
- [x] **100 % Abwärtskompatibilität für `RFS2` (Restore)**
  - Automatische Magic-Erkennung beim Wiederherstellen:
    - `"RFS2"` ➔ SHA-256 Verifikation (historische Splits aus C++ bleiben bitgenau lesbar und verifiziert).
    - `"RFS3"` ➔ BLKS-384 Verifikation (High-Speed Post-Quantum Standard).
- [x] **Hardware-Benchmark & Diagnose-Suite**
  - Neuer hardwarenaher Benchmark (`rfs --benchmark`) für ChaCha20, SIMD-XOR (3,98 GB/s) und BLKS-384.
  - Zweiphasige NIST- & Jitter-Entropieanalyse (`rfs --entropy-test`) und Datei-Kryptoanalyse (`rfs -a`).

---

### 🟡 Stufe 2: Wichtig (High-Priority – Nächster Meilenstein) – ✅ ABGESCHLOSSEN
- [x] **Fast-Verify Modus (`rfs --verify <teil1> <teil2>` bzw. `rfs verify <teil1> <teil2>`)**
  - Schnelle Integritäts- und Entschlüsselbarkeitsprüfung im RAM **ohne** Schreiben auf die Zielfestplatte implementiert.
- [x] **Unix Stdin/Stdout Streaming-Pipes**
  - Direkte Pipe-Unterstützung beim Splitten: `tar -czf - /data | rfs split - teil1.rfs teil2.rfs`
  - Direkte Rekonstruktion nach Stdout: `rfs restore teil1.rfs teil2.rfs -o - | tar -xzf -`
  - Kein temporäres Zwischenspeichern gigantischer Archive mehr erforderlich.
  - Subcommands (`split`, `restore`, `verify`) und klassische POSIX-Syntax nahtlos integriert.
- [x] **Entkoppelte Streaming-Pipeline (Zero-Copy Triple-Buffering Feintuning)**
  - Reader-, Crypto/SIMD- und Writer-Threads über gepoolte Puffer (`crossbeam-channel`) vollständig entkoppelt.
  - Zero-Heap-Allocation in der Streaming-Schleife, konstanter $O(1)$ Speicherbedarf.

---

### 🟢 Stufe 3: Empfohlen (Power-Features & Ergonomie) – ✅ ABGESCHLOSSEN
- [x] **N-Way Splitting (Aufteilung in 3, 4 oder N Teile)**
  - Beliebig viele Teile über One-Time-Pad Chain: $P = C_1 \oplus C_2 \oplus \dots \oplus C_n$.
  - Option `-n, --parts <ANZAHL>` (2 bis 64 Teile) in CLI integriert.
  - Vektorisierte SIMD-XOR Kaskadierung im Worker-Thread.
  - $N$-Way Stealth-Footer: $F_1 = \text{Plain} \oplus F_2 \oplus \dots \oplus F_N$. Alle $N$ Teile zwingend zur Rekonstruktion erforderlich; Fehlen oder Manipulation eines Teils wird sofort abgewiesen.
  - Dedizierte Integrationstests (`tests/n_way_tests.rs`) erfolgreich verifiziert.
- [x] **Maschinenlesbare JSON-Telemetrie (`--json`)**
  - Strukturierte NDJSON-Ausgabe auf `stderr` (analog zu `blkcp`) für Skripte, CI/CD und Agenten-Pipelines.
  - Events: `progress`, `finished` (inkl. `processed_bytes`, `elapsed_s`, `avg_speed_bps`, `checksum`, `num_parts`) und `error`.
  - Dedizierte Integrationstests in `tests/json_telemetry_tests.rs`.
- [x] **Interaktive Fortschrittsanzeige (`blkcp`-Style)**
  - 24-Zeichen breiter dynamischer ANSI-Balken (`[=====>----]`), Prozentanzeige, transferierte/totale Datenmengen, Durchsatzanzeige in MB/s bzw. GB/s und Live-ETA.
  - Dedizierte Stream-Anzeige bei Pipes mit unbekannter Länge.
- [x] **Erweiterte NIST SP 800-22 Entropieanalyse**
  - Ausbau des `-a / --analyze` Werkzeugs um NIST SP 800-22 Runs-Tests (Bit-Dynamik) und Block-Frequenztests ($M=128$).
  - Eigene analytische `erfc`-Implementierung und Wilson-Hilferty Chi-Square P-Wert-Transformation.
  - Optionale JSON-Ausgabe via `rfs -a <Datei> --json` für automatisierte Krypto-Audits.

---

### 🔵 Stufe 4: Feinschliff & Packaging – ✅ ABGESCHLOSSEN
- [x] **Direct I/O (`--direct` / `posix_fadvise`) auf Linux**
  - Sequentielles Read-Ahead und Page-Cache Bypass (`POSIX_FADV_SEQUENTIAL` / `POSIX_FADV_DONTNEED`) für Multi-Gigabyte-Dateien zur Schonung des Systemspeichers.
- [x] **Paketierung & Systemintegration**
  - Arch Linux / CachyOS PKGBUILD unter `packaging/arch/PKGBUILD` mit manpage-, license- und completion-Installern.
  - Shell-Completions für Bash (`completions/rfs.bash`), Zsh (`completions/_rfs`) und Fish (`completions/rfs.fish`).
  - Vollständige UNIX-Manpage (`docs/rfs.1`).
- [*] **Architektur-Entscheidung: Bewusster Verzicht auf $K$-aus-$N$ Threshold / Shamir**
  - Gewährleistet strikte *Plausible Deniability* (statistische Ununterscheidbarkeit von weißem Rauschen).
  - Fokus bleibt zu 100 % auf purem One-Time-Pad ($N$-aus-$N$ XOR-Chains).

---

### 🛡️ Stufe 5: Anti-Forensik & RFS4 Stealth-Format – ✅ ABGESCHLOSSEN
- [x] **Anti-Forensik Köderdateien (Decoys & Slot-Shuffling)**
  - Ununterscheidbare Rauschdateien mit 100 % ChaCha20-CSPRNG (`-d, --decoys` und Subcommand `rfs decoy`).
  - Intelligente Vorlagenerkennung: Exakte 1:1 Dateigröße für RFS-Shares bzw. automatische Berechnung von RFS4 + 4 KiB-Padding für Rohdateien.
  - ChaCha20 Fisher-Yates Slot-Shuffling: Reale Shares und Decoys werden unkorreliert auf Plätze verteilt.
- [x] **RFS4-Format mit eingebettetem Originaldateinamen**
  - 64-Byte RFS4-Trailer: Magic `"RFS4"`, Version `0x0400`, Originalgröße, BLKS-384 Digest und Dateinamenlänge.
  - Der Originaldateiname wird One-Time-Pad-verschlüsselt direkt vor dem Trailer über alle $N$ Teile abgelegt.
  - Automatische Wiederherstellung des Dateinamens direkt aus dem Footer bei `rfs restore` (ohne `-o`).
- [x] **4 KiB Cluster-Padding & `--pad-to <GRÖSSE>`**
  - Jede Share-Datei wird standardmäßig auf ein Vielfaches von 4.096 Bytes aufgefüllt (verhindert Bytegrößen-Korrelation auf Dateisystem-Ebene).
  - Beliebiges künstliches Aufblähen via `--pad-to` (z. B. 100M, 20G) zur gezielten Traffic-Verschleierung.
- [x] **Anonyme `<token6>.rfs` Dateibenennung**
  - Alle generierten Dateien tragen neutrale, unkorrelierte 6-stellige Hex-Tokens (z. B. `a9f4c2.rfs`, `7c1b3e.rfs`).
  - Dateisystem leakt null Informationen über Inhalt, Struktur oder Anzahl der Teile.

---

### 🧹 Stufe 6: Frühjahrsputz & Code-Modularisierung (In Umsetzung)
- [x] **Phase 1: Anti-Forensik & Naming Auslagerung**
  - `src/naming.rs`: Eindeutige Hex-Tokens, ChaCha20-Pfadshuffling, Zieldeduktion und Quell-Kollisionsschutz ausgelagert.
  - `src/decoy.rs`: Eigenständiges Decoy-Subsystem (Größenanalyse, Rauschgenerator, Vorlagenerkennung).
  - `src/pipeline.rs` von 1.196 auf 805 Zeilen verschlankt (-33 % Umfang).
  - 36/36 Tests grün, 0 Clippy-Warnungen.
- [ ] **Phase 2: Entropie-Modularisierung**
  - `src/entropy/` in `harvester.rs` (Jitter-Seed-Pool), `stats.rs` (NIST-Tests & Mathematik) und `report.rs` (Terminal-Reports) zerlegen.
- [ ] **Phase 3: CLI-Entflechtung**
  - `src/cli/` Submodul mit typisiertem Argument-Parsing, Validierung und Entlastung von `main.rs` (< 80 Zeilen).
- [ ] **Phase 4: Pipeline-Restrukturierung & Ringpuffer-Abstraktion**
  - `src/pipeline/` Submodul mit `buffer_pool.rs`, `split.rs` und `restore.rs`. Beseitigung redundanter Thread-Verwaltung.

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
