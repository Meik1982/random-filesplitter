# rfs - Random File Splitter (2026 Edition) 🛡️

**rfs** ist ein minimalistisches Tool zur **physischen Transportsicherung** und zum Splitting von Dateien. Es basiert auf dem Prinzip der **XOR-Verknüpfung**: Eine Datei wird in zwei Teile zerlegt, die für sich allein genommen wie weißes Rauschen erscheinen. Nur wer beide Teile besitzt, kann das Original bit-genau wiederherstellen.

## 🚀 Features (v1.1 Security & Performance Upgrade)

* **Plattformunabhängiger Entropie-Harvester:** Erntet ohne externe Abhängigkeiten echte CPU-Jitter-Entropie (Nanosekunden-Varianzen im Cache/Pipeline), kombiniert mit C++ `std::random_device` und ASLR-Speicherlayout.
* **ChaCha20 CSPRNG:** Kryptografisch sichere Pseudozufalls-Generierung mit vollem 256-Bit Key und 96-Bit Nonce (ersetzt den unsicheren Mersenne-Twister).
* **64-Bit / SIMD Fast-Path:** Hochoptimierte 64-Bit Vektor-XOR-Schleife mit sauberem Byte-Level Tail-Handling für Dateien beliebiger Bytegröße.
* **Stealth Padding:** Um die Analyse der ursprünglichen Dateigröße durch Dritte zu erschweren, wird jede Datei automatisch mit zufälligem Rauschen (1-100 KB) aufgefüllt.
* **Verschlüsselte Metadaten & Integrität:** Endianness-sichere Serialisierung der Dateigröße und **SHA-256 Integritätsprüfung**. Erkennt Manipulationen und Bit-Flips zuverlässig.
* **Fehlertolerante CLI:** Unterstützt beliebige Argument-Reihenfolge (`.rfs1 .rfs2` oder `.rfs2 .rfs1`) und prüft Dateigrößen vorab.
* **Echtzeit-Fortschrittsanzeige:** Nicht-blockierende Terminal-Progressbar mit Live-Übertragungsrate (MB/s).
* **Integrierter Hardware-Benchmark:** Schneller Selbsttest (`rfs --benchmark`) für Entropie-, ChaCha20-, XOR- und SHA-256-Durchsatz.
* **100% Portabel:** Reiner ISO C++11 Code ohne externe Abhängigkeiten, läuft auf Linux, Windows, macOS, ReactOS und BSD.

## 🛠️ Installation & Kompilierung

Da der Code keine externen Bibliotheken benötigt, reicht ein einfacher Aufruf des C++ Compilers.  
**Wichtig:** Um die maximale Geschwindigkeit (hunderte Megabyte pro Sekunde) zu erreichen, sollte der Compiler die Hardware-Features deiner CPU (wie AVX2/SIMD) nutzen. 

Nutze dafür diesen optimierten Befehl:

```bash
g++ -O3 -march=native rfs.cpp -o rfs
```

## 📖 Benutzung

### Datei sichern / Teilen
Das Programm erstellt aus einer Quelldatei zwei neue Dateien mit den Endungen `.rfs1` und `.rfs2`:

```bash
./rfs meine_daten.zip
```

### Datei wiederherstellen / Zusammenfügen
Gib einfach beide Teile an, um die Originaldatei wiederherzustellen. Das Tool prüft dabei automatisch die Integrität mittels SHA-256:

```bash
./rfs meine_daten.zip.rfs1 meine_daten.zip.rfs2
```

## ⚖️ Lizenz

Dieses Programm wurde von **Meik Augenblick** unter der **Lesser GNU General Public License (LGPL)** geschrieben.
