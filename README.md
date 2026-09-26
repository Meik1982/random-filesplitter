# rfs - Random File Splitter (v2.0.0 High-Performance & Security Edition) 🛡️

**rfs** ist ein hochoptimiertes, modulares und plattformunabhängiges C++11 System-Tool zur **physischen Transportsicherung** und kryptografischen Aufteilung von Dateien. Es basiert auf dem Prinzip der **Information-Theoretic Security via XOR**: Eine Datei wird in zwei Hälften zerlegt, die für sich allein genommen mathematisch ununterscheidbar von weißem Rauschen sind (100 % Plausible Deniability, Zero Fingerprint). Erst beim Zusammenführen beider Teile wird die Originaldatei bit-genau rekonstruiert.

---

## 🚀 Features & Architektur (v2.0.0 / RFS2)

* **Modulare Zero-Dependency C++11 Architektur:** Vollständig entkoppelte Module (`include/rfs/`, `src/`, `tests/`) ohne externe Bibliotheken. Kompiliert in unter 2 Sekunden auf Linux, Windows, macOS, BSD und ReactOS.
* **RFS2 Stealth Footer mit Sofort-Validierung:**
  * Die letzten 44 Bytes jeder Datei enthalten ge-XORte Metadaten: 4 Bytes Magic-Tag (`RFS2`), 32 Bytes SHA-256 Prüfsumme und 8 Bytes Original-Dateigröße (Little-Endian).
  * **Zero Fingerprint:** Jeder Metadaten-Byte wird einzeln mit einem Zufalls-Byte maskiert. Einzeln betrachtet bleibt jede Datei 100 % weißes Rauschen.
  * Beim Zusammenführen (`rfs file1 file2`) prüft das Tool den Magic-Tag in unter 1 Millisekunde und bricht bei falschen Dateien sofort ab.
* **ChaCha20 CSPRNG mit 8-Block AVX2-SIMD:** Vollständige Ausnutzung aller 8 Lanes der 256-Bit YMM-Register (512 Bytes pro Runde, **> 1,1 GB/s Durchsatz**) mit portablem 64-Bit-Fallback für Nicht-AVX2- und ARM-CPUs.
* **Double-Buffering Pipeline mit persistenten Worker-Threads:** Beseitigung jeglichen Thread-Erzeugungs-Overheads. Datenverarbeitung (ChaCha20/XOR), Disk-I/O und SHA-256 Hashing laufen parallel über feste Worker-Threads.
* **Gehärteter Entropie-Harvester:** Erntet Hardware-RNG (`std::random_device`), Monotonic Clocks, ASLR-Pointer und echten physikalischen L2/L3-Cache- und Bus-Jitter (2 MB Memory-Pool mit nicht-vorhersagbarem Sattolo-Permutationszyklus zur bewussten Aushebelung von Hardware-Stream-Prefetchern).
* **Vollständige Krypto-Hygiene:** Sichere Nullung (`secure_wipe_memory` mit Compiler-Memory-Barriere gegen Dead-Store-Elimination) aller Schlüssel-, Nonce-, Hash- und Klartext-Arbeitsspeicherpuffer im RAM.
* **Überschreibschutz & CLI-Flexibilität:**
  * Schutz vor versehentlichem Überschreiben bestehender Dateien (`-f / --force` zum Erzwingen).
  * Benutzerdefinierter Zielpfad (`-o / --output <pfad>`).
  * Versionsausgabe (`-V / --version`) und Hilfeseite (`-h / --help`).
* **Zweiphasige Diagnose-Suite (`--entropy-test`):**
  * *Phase 1:* Analyse des unkonditionierten CPU- und Memory-Timing-Jitters ($\sigma$, diskrete Buckets, Bit-Transitionsrate, Shannon-Entropie).
  * *Phase 2:* NIST-Statistik-Suite auf den ChaCha20-Schlüsselstrom (Shannon-Entropie, $\chi^2$-Anpassungstest, Bit-Balance, serielle Autokorrelation).
* **Hardware-Benchmark (`--benchmark`):** Schnelle Live-Messung der Durchsatzraten für Entropie, ChaCha20-SIMD, Fast-Path XOR, SHA-256 und Pipelining.

---

## 🛠️ Kompilierung & Installation

Das Projekt benötigt keine externen Abhängigkeiten, lediglich einen gängigen C++11-fähigen Compiler (`g++` oder `clang++`) und `make`.

### Mit Makefile (Empfohlen):
```bash
# Bauen (nutzt automatisch AVX2, falls vorhanden)
make -j$(nproc)

# Unit-Tests ausführen
make test

# Entropie-Diagnose & Hardware-Benchmark
make entropy
make benchmark

# Systemweite Installation (nach /usr/local/bin)
sudo make install
```

### Manuelle Kompilierung (Einzeiler):
```bash
# Mit AVX2-SIMD-Beschleunigung:
g++ -O3 -mavx2 -pthread -Iinclude src/*.cpp -o rfs

# Portabel für beliebige x86_64 / ARM / Raspberry Pi CPUs:
g++ -O3 -pthread -Iinclude src/*.cpp -o rfs
```

---

## 📖 Benutzung

### 1. Datei splitten (Verschlüsseln)
Erstellt aus einer Datei zwei scheinbar zufällige Rausch-Dateien (`.rfs1` und `.rfs2`):
```bash
rfs backup.tar.gz
```

### 2. Datei wiederherstellen (Entschlüsseln)
Rekonstruiert die Originaldatei, prüft den RFS2-Magic-Tag und verifiziert automatisch die SHA-256-Integrität:
```bash
rfs backup.tar.gz.rfs1 backup.tar.gz.rfs2
```

### 3. Benutzerdefinierter Zielpfad & Überschreiben erzwingen
```bash
rfs backup.tar.gz.rfs1 backup.tar.gz.rfs2 -o /pfad/zu/ziel.tar.gz -f
```

### 4. Nur Integrität prüfen (Dry-Run / Verify)
Prüft die Validität beider Teile ohne Schreibzugriff auf die Festplatte:
```bash
rfs --verify backup.tar.gz.rfs1 backup.tar.gz.rfs2
```

### 5. Entropie-Diagnose & NIST-Kryptoanalyse
```bash
rfs --entropy-test
```

### 6. Hardware-Benchmark ausführen
```bash
rfs --benchmark
```

---

## 📂 Projektstruktur

```text
random-filesplitter/
├── include/rfs/
│   ├── types.hpp        # RFS2-Konstanten, Magic-Tag, Endianness & Secure Wipe
│   ├── chacha20.hpp     # ChaCha20 CSPRNG (AVX2 8-Block SIMD & 64-Bit Fallback)
│   ├── sha256.hpp       # SHA-256 Hashing-Engine
│   ├── entropy.hpp      # UniversalEntropyHarvester & Jitter-Diagnose
│   ├── splitter.hpp     # Kern-Logik: Split, Merge, Verify & Benchmark
│   └── progress.hpp     # Nicht-blockierende Terminal-Fortschrittsanzeige
├── src/
│   ├── chacha20.cpp
│   ├── sha256.cpp
│   ├── entropy.cpp
│   ├── splitter.cpp
│   └── main.cpp         # CLI-Parser
├── tests/
│   └── test_crypto.cpp  # Testsuite für NIST-Vektoren, E2E & Magic-Tag
├── .github/workflows/
│   └── build.yml        # CI-Matrix für Linux, Windows & macOS + Release-Deploy
└── Makefile
```

---

## ⚖️ Lizenz

Dieses Programm wurde von **Meik Augenblick** unter der **Lesser GNU General Public License (LGPL v3)** geschrieben.
