# rfs - Random File Splitter (2026 High-Performance & Security Edition) 🛡️

**rfs** ist ein hochoptimiertes, plattformunabhängiges System-Tool zur **physischen Transportsicherung** und zum kryptografischen Aufteilen von Dateien. Es basiert auf dem Prinzip der **XOR-Verknüpfung**: Eine Datei wird in zwei Teile zerlegt, die für sich allein genommen mathematisch ununterscheidbar von weißem Rauschen sind. Erst beim Zusammenführen beider Teile wird die Originaldatei bit-genau rekonstruiert.

## 🚀 Features & Architektur (v1.2)

* **Plattformunabhängiger Entropie-Harvester:** Erntet ohne externe Bibliotheken physikalische CPU- und Cache-Jitter-Entropie (Pointer-Chasing über einen 1 KB Aligned-Memory-Pool zur Provokation echter L2/L3- und DRAM-Bus-Latenzen), kombiniert mit Hardware-Entropie (`std::random_device`), Monotonic Clocks und ASLR-Speicherlayout.
* **ChaCha20 CSPRNG mit AVX2-SIMD:** Kryptografisch sichere 256-Bit-Zufallsgenerierung mit nativer 4-Block-Parallelverarbeitung via AVX2 (bis zu ~850 MB/s Krypto-Durchsatz) und portablem 64-Bit-Fallback.
* **Multi-Threaded Pipelining & Asynchrones I/O:** Vollständig entkoppeltes I/O-Streaming via `std::async`/`std::future` (Double-Buffering). Festplatten-Lese-/Schreibzyklen und CPU-Krypto-Berechnungen laufen parallel.
* **Paralleles Hashing:** SHA-256 Integritätsprüfung wird blockweise in einem separaten Thread ausgeführt, ohne den Krypto-Stream zu blockieren.
* **Explicit Secure Wipe:** Krypto-Hygiene durch volatiles Überschreiben (`secure_wipe_memory`) aller sensitiven Schlüssel-, Nonce- und Hash-Puffer im RAM.
* **Stealth Padding:** Jede Datei wird mit zufälligem Rauschen (1-100 KB) aufgefüllt, um die exakte Dateigröße vor Metadaten-Analysen zu verschleiern.
* **Integrierter Verify-Modus (`--verify`):** Schnelle Prüfung der Datei-Integrität und SHA-256-Prüfsumme beider Hälften, ohne die Datei auf die Festplatte schreiben zu müssen.
* **Entropie- & Kryptoanalyse-Diagnose (`--entropy-test`):** Zweiphasige Validierung der physikalischen Entropiequalität:
  - *Phase 1:* Analyse der unkonditionierten CPU-Jitter-Rohdaten (Timing-Streuung $\sigma$, Min-Entropie-Buckets, LSB-Bitflips). Erkennt starre Emulatoren oder deterministische VMs.
  - *Phase 2:* NIST-Statistik-Suite auf den Schlüsselstrom (Shannon-Entropie, Chi-Quadrat $\chi^2$, Bit-Balance, serielle Autokorrelation).
* **Echtzeit-Fortschrittsanzeige:** Nicht-blockierende Terminal-Progressbar mit Live-Durchsatzanzeige (`MB/s`).
* **Hardware-Benchmark (`--benchmark`):** Schneller Leistungstest für Entropie-, ChaCha20-, XOR-, SHA-256- und Pipeline-Durchsatz.
* **100% Portabel:** Reiner ISO C++11 Code ohne externe Abhängigkeiten für Linux, Windows, macOS, ReactOS und BSD.

---

## 🛠️ Kompilierung & Installation

Da der Code keine externen Bibliotheken benötigt, reicht ein gängiger C++ Compiler.

### Für maximale Performance (AVX2-optimiert):
```bash
g++ -O3 -mavx2 rfs.cpp -o rfs -pthread
```

### Portabel für beliebige CPUs (Fallback):
```bash
g++ -O3 rfs.cpp -o rfs -pthread
```

---

## 📖 Benutzung

### 1. Datei splitten (Verschlüsseln)
Erstellt aus einer Quelldatei zwei Teile mit den Endungen `.rfs1` und `.rfs2`:
```bash
./rfs archiv.tar.gz
```

### 2. Datei wiederherstellen (Entschlüsseln)
Rekonstruiert die Originaldatei und verifiziert automatisch die SHA-256 Integrität (beliebige Argument-Reihenfolge):
```bash
./rfs archiv.tar.gz.rfs1 archiv.tar.gz.rfs2
```

### 3. Nur Integrität prüfen (ohne Schreiben auf Disk)
Überprüft, ob beide Teile intakt und fehlerfrei zusammenpassen:
```bash
./rfs --verify archiv.tar.gz.rfs1 archiv.tar.gz.rfs2
```

### 4. Entropie- & Krypto-Qualitätsanalyse
Validiert den Hardware-Jitter und analysiert den Zufallsstrom nach NIST-Kriterien:
```bash
./rfs --entropy-test
```

### 5. Hardware-Benchmark ausführen
Testet die maximale Krypto- und I/O-Geschwindigkeit deines Systems:
```bash
./rfs --benchmark
```

---

## ⚖️ Lizenz

Dieses Programm wurde von **Meik Augenblick** unter der **Lesser GNU General Public License (LGPL)** geschrieben.
