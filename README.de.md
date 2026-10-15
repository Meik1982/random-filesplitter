# rfs - Random File Splitter (v3.1.0 Post-Quantum & High-Performance Rust Edition) 🛡️

[English](README.md) | **Deutsch**

[![CI & Build RFS Binaries](https://github.com/Meik1982/random-filesplitter/actions/workflows/build.yml/badge.svg)](https://github.com/Meik1982/random-filesplitter/actions/workflows/build.yml)
[![License: LGPL v3](https://img.shields.io/badge/License-LGPL_v3-blue.svg)](https://www.gnu.org/licenses/lgpl-3.0)
[![Rust](https://img.shields.io/badge/Rust-2021_Edition-orange.svg)](https://www.rust-lang.org)
[![Post-Quantum Hash](https://img.shields.io/badge/Hash-BLKS--384-brightgreen.svg)](https://github.com/Meik1982/blks)

**rfs** ist ein hochperformantes, modulares Systemwerkzeug für **physische Transportsicherheit**, kryptografische Aufteilung und bitgenaue Wiederherstellung von Dateien und Unix-Streams.

Es basiert auf dem mathematischen Fundament der **informationstheoretischen Sicherheit via One-Time-Pad-Kette ($N$-aus-$N$ XOR)** und **General Access Linear Secret Sharing über $\mathbb{F}_2$**:
Eine Datei wird in $N$ Teile ($N \ge 2$) zerlegt, wobei jede einzelne Share mathematisch ununterscheidbar von thermischem Rauschen ist (**100 % glaubhafte Abstreitbarkeit, kein forensischer Fingerabdruck**). Der Originalklartext kann ausschließlich rekonstruiert werden, wenn **alle $N$ Shares** zusammengeführt werden. Fehlt auch nur ein einziger Teil, ist das Geheimnis mathematisch unlösbar.

---

## 🚀 Kernfeatures in v3.1.0

* **Kombinatorische Auto-Discovery & Assembly Engine (`rfs scan`):**
  * Liest ausschließlich die 64-Byte Trailer im RAM, ohne Multi-Gigabyte-Nutzdaten sequentiell durchscannen zu müssen.
  * Erkennt in Millisekunden alle gültigen $N$-Way OTP Sets aus beliebigen Dateiordnern und trennt echte Shares automatisch von Köderdateien (Decoys).
  * **1-Klick Auto-Restore:** `rfs scan *.rfs -r -o ./wiederhergestellt/` entpackt alle entdeckten Payloads vollautomatisch.
* **Glaubhafte Abstreitbarkeit & Köder-Synthese (`rfs forge` / Rubber-Hose-Resilienz):**
  * Nutzt die informationstheoretische Sicherheit des One-Time-Pads: Gegeben seien $K$ beschlagnahmte Shares und eine harmlose Köderdatei (z. B. Urlaubsbilder oder ein Dummy-PDF). `rfs forge` synthetisiert die exakt passende Gegen-Share.
  * Das Zusammenführen der beschlagnahmten Shares mit der synthetisierten Fake-Share stellt die Köderdatei mit **100 % BLKS-384 PQ-Integrität** (grüner Status) wieder her. Ein Angreifer kann mathematisch unmöglich beweisen, dass jemals ein anderes Original existiert hat.
* **Simultane Klartext-Köder beim Splitten (`rfs split --decoy-reveal <DATEI>`):**
  * Webt direkt bei der Erstellung einen echten Klartext-Köder ein.
  * Echte Teilmengen rekonstruieren das Originalgeheimnis; die Köder-Teilmenge rekonstruiert die harmlose Köderdatei.
* **Moderne Slint Desktop-GUI (`rfs-gui`):**
  * Native, GPU-beschleunigte Desktop-Oberfläche mit 3 Reitern: `📦 Aufteilen (Split)`, `🔓 Wiederherstellen & Scanner (Restore)` und `🎭 Täuschung (Forge)`.
  * Ausgeliefert mit transparentem Kristall-Icon und vollständiger `.desktop`-Systemintegration.
* **Post-Quantum Stealth Footer (RFS4):**
  * Nutzt **BLKS-384** (384-Bit Post-Quantum Merkle-Tree Hashing) statt veraltetem SHA-256 und eliminiert Prüfsummen-Engpässe (**3,3x schneller als SHA-256**).
  * Der 64-Byte Stealth-Metadaten-Trailer wird über alle $N$ Shares hinweg XOR-verschlüsselt. Isoliert betrachtet besteht jede Share zu 100 % aus Entropie ohne Klartext-Header oder Magic Bytes.
  * Sofortiger Sub-Millisekunden-Abbruch (< 1 ms) bei manipulierten oder unvollständigen Shares.
* **$N$-Way One-Time-Pad Splitting (2 bis 64 Shares):**
  * Beliebige Aufteilung in 3, 4 oder $N$ Teile via `-n, --parts <ANZAHL>`.
  * Shares $2 \dots N$ werden mit unkorreliertem ChaCha20-CSPRNG-Zufall befüllt; Share 1 schließt die Kette via SIMD-beschleunigtem XOR ($P = C_1 \oplus C_2 \oplus \dots \oplus C_N$).
* **Entkoppelte 3-Stufen-Pipeline & Parallel Disk Fanout:**
  * Dedizierte Worker-Threads für Reader, SIMD/Krypto-Engine und Writer, synchronisiert über gepufferte Kanäle (`crossbeam-channel` mit allokationsfreiem Triple-Buffering).
  * Echte I/O-Parallelität über unabhängige physische Mountpoints (z. B. separate USB-Sticks oder NVMe-Laufwerke).
  * Gesättigte Speicherbandbreite: bis zu **1,85 GB/s ChaCha20** und **~4,0 GB/s SIMD-XOR**.
* **Swap-Resilienz via Memory-Locking (`--mlock`):**
  * Sperrt kryptografische Pufferpools via POSIX `mlock` fest im physischen RAM, um Auslagerungen sensibler Daten auf Swap-Partitionen zu verhindern.
* **Unix-Streaming-Pipes (POSIX `-` Unterstützung):**
  * Nahtlose Integration in Unix-Pipelines: liest direkt von `stdin` und schreibt nach `stdout`.
* **Maschinenlesbare NDJSON-Telemetrie (`--json`):**
  * Strukturierte JSON-Ereignisse auf `stderr` (`progress`, `finished`, `error`) mit Bytezählern, Durchsatz, Live-ETA und Prüfsummen für Agenten- und Automations-Pipelines.
* **Interaktiver ANSI-Fortschrittsbalken:**
  * Dynamischer Terminal-Balken mit Prozentanzeige, Bytezählern, Live-Übertragungsrate (MB/s / GB/s) und Restzeit.
* **Fortschrittliche NIST SP 800-22 Entropie-Diagnostik:**
  * Zwei-Phasen Systemdiagnostik (`rfs --entropy-test`) und Datei-Entropieanalyse (`rfs -a <datei>`) mit Runs-Tests, Block-Frequency-Tests ($M=128$), analytischem `erfc` und Wilson-Hilferty Chi²-Approximation.
* **RFS4-Format mit eingebettetem Dateinamen & 4-KiB-Cluster-Padding:**
  * Der originale Dateiname wird direkt im Stealth-Trailer eingebettet und informationstheoretisch über alle Shares verschlüsselt.
  * Jede Share wird auf ein Vielfaches von **4 KiB (4.096 Bytes Cluster-Ausrichtung)** mit ChaCha20-Rauschen aufgefüllt – verhindert Dateigrößen-Korrelationsanalysen auf Dateisystemebene.
  * Optionales `--pad-to <GRÖSSE>` bläht Shares auf eine exakte Zielgröße auf (z. B. `100M`, `20G`).
* **Anonyme Anti-Forensik-Namensgebung (`<token6>.rfs`):**
  * Shares und Decoys nutzen standardmäßig unkorrelierte 6-stellige Hex-Tokens (z. B. `a9f4c2.rfs`, `7c1b3e.rfs`).
* **100 % Abwärtskompatibilität:**
  * Erkennt und restauriert historische RFS3- und RFS2-Archive (60B / 44B Footer, SHA-256 / BLKS-384) früherer Versionen bitgenau.

---

## 💻 Verwendung

### 1. Dateien aufteilen (RFS4 N-Way One-Time-Pad)
```bash
# In 2 anonyme Shares aufteilen (erzeugt z. B. a9f4c2.rfs, 7c1b3e.rfs mit 4 KiB Cluster-Padding)
rfs split daten.iso

# In 3 Shares aufteilen und auf exakt 50 MB aufblähen
rfs split -n 3 daten.iso --pad-to 50M

# In 3 Shares aufteilen mit simultanem Klartext-Köder (Täuschung)
rfs split -n 3 geheimnis.kdbx --decoy-reveal rezept.txt -o /media/backup/

# Mit 3 Köderdateien mischen (erzeugt 6 ununterscheidbare Dateien mit Zufallstokens)
rfs split -n 3 daten.iso -d 3
```

### 2. Symmetrisches Multi-Klartext-Splitting (General Access LSSS über GF(2))
Ermöglicht das gleichzeitige, symmetrische Einbetten von $N$ beliebigen Klartextdateien in $M$ Shares mit Schwellenwert $T$ (z. B. 3 aus 5). Jede autorisierte Kombination rekonstruiert bitgenau ihre zugewiesene Datei; unberechtigte Kombinationen ergeben reines Rauschen.

```bash
# 3 Dateien symmetrisch auf 5 Shares aufteilen (3-aus-5 Schwellenwert):
rfs split tresor.kdbx urlaub.pdf rechnung.xlsx -n 5 -T 3 -o ./shares/

# Alle 3 Dateien vollautomatisch scannen und bitgenau entpacken:
rfs scan ./shares/*.rfs -r -o ./wiederhergestellt/
```

> **📌 Informationstheoretische Schranke ($M \ge N + 1$):**  
> Nach dem Shannon-Theorem für lineare Geheimnisteilung über $\mathbb{F}_2$ werden für $N$ Klartextdateien **mindestens $M \ge N + 1$ Shares** benötigt.  
> Der zusätzliche $+1$ Share liefert die mathematisch notwendige Dimension für das unkorrelierte ChaCha20-Zufallsrauschen (One-Time-Pad). Ohne diese Dimension gäbe es keine Entropiebasis und die Dateien lägen unmaskiert vor.

### 3. Auto-Discovery & Rekonstruktion (`rfs scan`)
```bash
# Analysiert alle .rfs-Dateien in einem Ordner und listet gefundene Sets in Millisekunden auf
rfs scan /media/usb/*.rfs

# Scannt und entpackt alle entdeckten gültigen Sets vollautomatisch in einen Zielordner
rfs scan /media/usb/*.rfs -r -o ./wiederhergestellt/
```

### 4. Glaubhafte Abstreitbarkeit & Köder-Synthese (`rfs forge`)
```bash
# Beschlagnahmte Share 'share1.rfs' + harmloser Köder 'urlaub.pdf' -> erzeugt 'fake_share2.rfs'
rfs forge share1.rfs --reveal-as urlaub.pdf -o fake_share2.rfs

# Wiederherstellung mit der gefälschten Share stellt bitgenau urlaub.pdf mit BLKS-384 Integrität her:
rfs restore share1.rfs fake_share2.rfs
```

### 5. Unix-Streaming-Pipes
```bash
# Stdin direkt in 4 Shares auf die Festplatte streamen
tar -czf - /daten | rfs split -n 4 - -o backup

# Stream direkt nach Stdout rekonstruieren ohne temporäre Zwischendateien
rfs restore backup.*.rfs -o - | tar -xzf -
```

### 6. Integritätsprüfung (ohne Festplattenzugriff)
```bash
# BLKS-384 Post-Quantum Integrität im RAM prüfen
rfs verify share1.rfs share2.rfs share3.rfs
```

### 6. Desktop-GUI
```bash
# Startet die native Slint Desktop-Oberfläche
rfs-gui
```

---

## 🏗️ Architektur & Mathematisches Fundament

Ausführliche mathematische Beweise und technische Spezifikationen finden sich unter:
* **[docs/lsss-matrix-konzept.de.md](docs/lsss-matrix-konzept.de.md):** Informationstheoretischer Sicherheitsbeweis (Shannon Perfect Secrecy $I(\mathbf{P}; \vec{y}^T \mathbf{C}) = 0$) & Bit-parallele $\mathbb{F}_2$ Lineare Secret Sharing Matrix.
* **[docs/articles/zero-allocation-pipeline-rust.md](docs/articles/zero-allocation-pipeline-rust.md):** Technische Tiefenanalyse der SIMD-beschleunigten Zero-Allocation Streaming-Pipeline.

---

## 📜 Lizenz

Copyright (c) 2026 Meik Augenblick.  
Lizenziert unter der **GNU Lesser General Public License v3.0 oder höher (LGPL v3)**.
