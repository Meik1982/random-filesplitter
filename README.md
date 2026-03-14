# rfs - Random File Splitter (2026 Edition) 🛡️

**rfs** ist ein minimalistisches, hochsicheres Datei-Verschlüsselungs- und Splitting-Tool. Es basiert auf dem Prinzip des **One-Time-Pads (XOR)**: Eine Datei wird in zwei Teile zerlegt, die für sich allein genommen mathematisch unknackbares, weißes Rauschen darstellen. Nur wer beide Teile besitzt, kann das Original wiederherstellen.

## 🚀 Neue Features (v1.0 Stealth Upgrade)

* **Kryptografischer Zufall:** Nutzt den modernen `std::mt19937_64` Generator, initialisiert durch echte Hardware-Entropie (`std::random_device`).
* **Stealth Padding:** Um die Analyse der Dateigröße zu verhindern, wird jede Datei automatisch mit zufälligem Rauschen (1-100 KB) aufgefüllt.
* **Verschlüsselte Metadaten:** Die Information über die ursprüngliche Dateigröße wird verschlüsselt am Ende der Dateien versteckt. Dies ermöglicht eine bit-genaue Rekonstruktion ohne Padding-Reste.
* **Performance-Turbo:** Optimierte Byte-Verarbeitung für blitzschnelles Verschlüsseln auch bei großen Dateien.
* **Cross-Plattform:** Reiner C++ Code ohne externe Abhängigkeiten. Perfekt für Linux (CachyOS, Debian etc.) und Windows.

## 🛠️ Installation & Kompilierung

Da der Code keine externen Bibliotheken benötigt, reicht ein einfacher Aufruf des C++ Compilers. 
**Wichtig:** Um die maximale Geschwindigkeit (hunderte Megabyte pro Sekunde) zu erreichen, muss der Compiler die Hardware-Features deiner CPU (wie AVX2/SIMD) freischalten. 

Nutze dafür diesen optimierten Befehl:

```bash
g++ -O3 -march=native rfs.cpp -o rfs
```

## 📖 Benutzung

### Verschlüsseln / Teilen
Das Programm erstellt aus einer Quelldatei zwei neue Dateien mit den Endungen `.rfs1` und `.rfs2`:

```bash
./rfs meine_daten.zip
```

### Entschlüsseln / Zusammenfügen
Gib einfach beide Teile an, um die Originaldatei wiederherzustellen:

```bash
./rfs meine_daten.zip.rfs1 meine_daten.zip.rfs2
```

## ⚖️ Lizenz

Dieses Programm wurde von **Meik Augenblik** unter der **Lesser GNU General Public License (LGPL)** geschrieben.
