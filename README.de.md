# rfs - Random File Splitter (v3.0.0 Post-Quantum & High-Performance Rust Edition) 🛡️

[English](README.md) | **Deutsch**

[![CI & Build RFS Binaries](https://github.com/Meik1982/random-filesplitter/actions/workflows/build.yml/badge.svg)](https://github.com/Meik1982/random-filesplitter/actions/workflows/build.yml)
[![License: LGPL v3](https://img.shields.io/badge/License-LGPL_v3-blue.svg)](https://www.gnu.org/licenses/lgpl-3.0)
[![Rust](https://img.shields.io/badge/Rust-2021_Edition-orange.svg)](https://www.rust-lang.org)
[![Post-Quantum Hash](https://img.shields.io/badge/Hash-BLKS--384-brightgreen.svg)](https://github.com/Meik1982/blks)

**rfs** ist ein hochperformantes, modulares Systemwerkzeug zur **physischen Transportsicherung**, kryptografischen Aufteilung und bitgenauen Rekonstruktion von Dateien und Datenströmen.

Es basiert auf dem mathematischen Prinzip der **Information-Theoretic Security via One-Time-Pad Chain ($N$-aus-$N$ XOR)**:
Eine Datei wird in $N$ Teile zerlegt ($N \ge 2$), von denen jeder einzelne Teil mathematisch ununterscheidbar von weißem Rauschen ist (**100 % Plausible Deniability, Zero Fingerprint**). Erst wenn **alle $N$ Teile** zusammengeführt werden, wird das Original bitgenau rekonstruiert. Fehlt auch nur ein einziger Teil, ist das Geheimnis mathematisch unlösbar.

---

## 🚀 Kernfeatures in v3.0.0 (Rust Rewrite)

* **Post-Quantum Stealth-Footer (RFS3 / RFS4):**
  * Verwendet **BLKS-384** (384-Bit Post-Quantum Merkle-Tree Hashing) anstelle von SHA-256. Beseitigt den früheren Hash-Flaschenhals vollständig (**3,3x schneller als SHA-256**).
  * Der 64-Byte Stealth-Trailer (RFS4) ist $N$-fach über alle Teile ge-XORt. Einzeln betrachtet bleibt jede Datei 100 % Rauschen ohne Magic-Header oder Klartextspuren.
  * Sofort-Abbruch (< 1 ms) bei nicht zusammengehörigen oder unvollständigen Dateien.
* **$N$-Way One-Time-Pad Splitting (2 bis 64 Teile):**
  * Beliebige Aufteilung in 3, 4 oder $N$ Teile via `-n, --parts <ANZAHL>`.
  * Teile $2 \dots N$ werden mit unkorreliertem ChaCha20-CSPRNG-Schlüsselstrom befüllt; Teil 1 schließt die Kette mit SIMD-beschleunigtem XOR ($P = C_1 \oplus C_2 \oplus \dots \oplus C_N$).
* **Entkoppelte 3-Stufen Zero-Allocation Pipeline & Paralleler Disk-Fanout:**
  * Dedizierte Threads für Reader, Krypto-Worker und parallele Disk-Writer, synchronisiert über gebundene Ringpuffer (`crossbeam-channel` mit Triple-Buffering).
  * Paralleles Schreiben und Lesen über getrennte physische Mountpoints (z. B. unabhängige USB-Sticks).
  * Bis zu **1,85 GB/s ChaCha20** und **~4,0 GB/s SIMD-XOR**.
* **Swap-Resilienz via Memory-Locking (`--mlock`):**
  * Sperrt kryptografische Puffer im physischen RAM via POSIX `mlock`, um Auslagerungen von sensiblen Klartextdaten und OTP-Zufallsströmen in Swap-Partitionen oder Ruhezustands-Abbilder hardwareseitig zu unterbinden.
* **Unix Streaming-Pipes (POSIX `-` Support):**
  * Nahtlose Integration in Unix-Pipelines: Liest von `stdin` und schreibt nach `stdout`.
  * Dateigröße muss vorab nicht bekannt sein; In-Flight BLKS-384 Hashing puffert die Metadaten bis zum Stream-Ende.
* **Maschinenlesbare NDJSON-Telemetrie (`--json`):**
  * Strukturierte JSON-Lines auf `stderr` (`progress`, `finished`, `error`) mit Bytezählern, Durchsatz, Live-ETA und Hashes für Skripte und KI-Agenten.
* **Interaktive Fortschrittsanzeige (`blkcp`-Style):**
  * Dynamischer 24-Zeichen ANSI-Fortschrittsbalken mit Prozentanzeige, formatierter Bytezahl, Live-Geschwindigkeit (MB/s / GB/s) und ETA.
* **Erweiterte NIST SP 800-22 Entropieanalyse:**
  * Zweiphasige Diagnose (`rfs --entropy-test`) und Datei-Audit (`rfs -a <Datei>`) mit Runs-Tests, Block-Frequenztests ($M=128$), analytischer `erfc`-Funktion und Wilson-Hilferty Chi²-Transformation.
* **RFS4-Format mit eingebettetem Dateinamen & 4 KiB Cluster-Padding:**
  * Der Original-Dateiname wird direkt im Stealth-Footer hinterlegt und über alle $N$ Teile informationstheoretisch per One-Time-Pad verschlüsselt ($F_1 = \text{Plain} \oplus F_2 \oplus \dots \oplus F_N$).
  * Jede Share-Datei wird automatisch auf ein Vielfaches von **4 KiB (4.096 Bytes Cluster-Alignment)** mit ChaCha20-Zufall aufgefüllt – verhindert jegliche Dateigrößen-Korrelation auf Byte-Ebene.
  * Mit `--pad-to <GRÖSSE>` können Shares auf eine exakte Bytegröße (z. B. `100M`, `20G`) aufgebläht werden.
* **Neutrales Anti-Forensik Namensschema (`<token6>.rfs`):**
  * Shares und Decoys erhalten standardmäßig unkorrelierte 6-stellige Zufalls-Tokens (z. B. `a9f4c2.rfs`, `7c1b3e.rfs`).
  * Das Dateisystem verrät weder den ursprünglichen Dateinamen, noch die Anzahl der Teile, noch welche Dateien echte Shares und welche Köder sind.
* **Automatische Wiederherstellung:**
  * `rfs restore a9f4c2.rfs 7c1b3e.rfs` liest den echten Originaldateinamen bitgenau aus dem Footer und legt die Datei automatisch unter ihrem ursprünglichen Namen ab.
* **100 % Abwärtskompatibilität:**
  * Rekonstruiert historische RFS3- und RFS2-Archive (60B / 44B Footer, SHA-256 / BLKS-384) aus Vorversionen automatisch und bitgenau.
* **Anti-Forensik Köderdateien (Decoys & Traffic-Obfuscation):**
  * Erzeugung beliebiger ununterscheidbarer Köderdateien mit 100 % ChaCha20-Zufallsrauschen (`-d, --decoys` beim Splitten oder Subcommand `rfs decoy`).
  * Intelligente Mustererkennung: Berechnet bei Rohdateien automatisch die künftige Share-Größe (`Originalgröße + 60 Bytes Stealth-Footer`) und übernimmt bei RFS-Shares die Dateigröße exakt 1:1.
  * Zerstört Traffic-Analysen und lässt Abhörer im Unklaren darüber, wie viele und welche Dateien echte Geheimnis-Shares sind.

---

## 💻 Verwendung

### 1. Dateien splitten (RFS4 N-Way One-Time-Pad)
```bash
# In 2 neutrale Teile aufteilen (erzeugt z. B. a9f4c2.rfs, 7c1b3e.rfs mit 4 KiB Cluster-Padding)
rfs split datei.iso

# In 3 Teile aufteilen und auf exakt 50 MB aufblähen
rfs split -n 3 datei.iso --pad-to 50M

# Mit 3 Köderdateien verwürfeln (insg. 6 ununterscheidbare Dateien mit Zufalls-Tokens)
rfs split -n 3 datei.iso -d 3

# Mit Swap-Resilienz (mlock) und parallelem Disk-Fanout auf unabhängige Mounts
rfs split -n 3 --mlock datei.iso /media/usb1/pA.rfs /media/usb2/pB.rfs /media/usb3/pC.rfs
```

### 2. Dateien wiederherstellen & verifizieren
```bash
# Stellt den Original-Dateinamen automatisch aus dem RFS4-Footer wieder her:
rfs restore a9f4c2.rfs 7c1b3e.rfs

# In spezifische Zieldatei wiederherstellen (oder '-' für stdout)
rfs restore a9f4c2.rfs 7c1b3e.rfs -o wunschname.iso

# Integrität im RAM prüfen ohne Disk-Schreibzugriff
rfs verify a9f4c2.rfs 7c1b3e.rfs
```

### 3. Unix Streaming-Pipes
```bash
# Tar-Archiv direkt beim Erstellen in 4 Teile streamen
tar -czf - /var/data | rfs split -n 4 - -o backup

# Aus 4 Teilen direkt nach stdout entpacken
rfs restore backup.rfs1 backup.rfs2 backup.rfs3 backup.rfs4 -o - | tar -xzf -
```

### 4. Köderdateien (Decoys) & Anti-Forensik
```bash
# Beim Splitten sofort 4 Köder mitgenerieren (insg. 7 Dateien)
rfs split -n 3 geheim.iso -d 4

# Nachträglich Köder basierend auf einer Rohdatei erstellen (+64 Bytes Footer auto-berechnet)
rfs decoy -t vertrag.pdf -c 5

# Nachträglich Köder basierend auf einem RFS-Share erstellen (1:1 Bytegröße)
rfs decoy -t 7c1b3e.rfs -c 3

# Köder mit expliziter Zielgröße erzeugen (z. B. 50 MB)
rfs decoy -s 50M -c 2 -o fake_share
```

### 5. Maschinenlesbare Telemetrie (--json)
```bash
rfs split -n 3 riesig.iso --json
# Ausgabe auf stderr:
# {"event":"progress","action":"Split","processed_bytes":524288000,"total_bytes":1048576000,"percent":50.00,"speed_bps":1850230120,"elapsed_s":0.28,"eta_s":0.2}
# {"event":"finished","action":"Split","processed_bytes":1048576000,"elapsed_s":0.5512,"avg_speed_bps":1902340123,"num_parts":3,"checksum":{"algorithm":"blks-384","digest":"..."}}
```

### 6. Kryptoanalyse & Benchmarks
```bash
# NIST SP 800-22 Datei-Entropieanalyse
rfs -a datei.iso.rfs1

# Zweiphasige System- und Hardware-Entropiediagnose
rfs --entropy-test

# Hardware-Benchmark (SIMD ChaCha20, XOR, BLKS-384)
rfs --benchmark
```

---

## 🛠️ Kompilierung & Installation

### Voraussetzungen
* Rust Toolchain (Edition 2021, MSRV 1.75+)

### Aus dem Quellcode bauen
```bash
git clone https://github.com/Meik1982/random-filesplitter.git
cd random-filesplitter
cargo build --release

# Binary testen
./target/release/rfs --version
./target/release/rfs --benchmark
```

### Arch Linux / CachyOS (makepkg)
```bash
cd packaging/arch
makepkg -si
```

---

## 📊 Kryptoanalytischer Nachweis (Plausible Deniability)

Für jeden Split-Teil gelten nachweisbar folgende statistische Schwellenwerte:

| Metrik | Sollwert / Ideal | Typischer RFS-Messwert | Status |
| :--- | :--- | :--- | :--- |
| **Shannon-Entropie** | $\approx 8{,}000000$ Bits/Byte | **$7{,}99983$ Bits/Byte** | ✅ Bestanden |
| **Chi-Quadrat ($\chi^2$)** | $180{,}0 \dots 330{,}0$ ($p = 0{,}05 \dots 0{,}95$) | **$248{,}32$** | ✅ Bestanden |
| **Arithmetischer Mittelwert** | $127{,}500$ | **$127{,}498$** | ✅ Bestanden |
| **Bit-Balance (1/0)** | $50{,}000\ \%$ | **$50{,}016\ bait\%$** | ✅ Bestanden |
| **NIST Runs-Test** | $p \ge 0{,}01$ | **$p = 0{,}627$** | ✅ Bestanden |
| **NIST Block-Frequenz ($M=128$)** | $p \ge 0{,}01$ | **$p = 0{,}172$** | ✅ Bestanden |

---

## 📜 Lizenz & Urheberrecht

Copyright (c) 2026 Meik Augenblick.  
Lizenziert unter der **GNU Lesser General Public License v3.0 (LGPL v3)**.
