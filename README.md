# rfs - Random File Splitter (2026 Edition) 🛡️

**rfs** ist ein minimalistisches Tool zur **physischen Transportsicherung** und zum Splitting von Dateien. Es basiert auf dem Prinzip der **XOR-Verknüpfung**: Eine Datei wird in zwei Teile zerlegt, die für sich allein genommen wie weißes Rauschen erscheinen. Nur wer beide Teile besitzt, kann das Original bit-genau wiederherstellen.

## 🚀 Features (v1.0 Stealth Upgrade)

* **Statistischer Zufall:** Nutzt den modernen `std::mt19937_64` Generator, initialisiert durch Hardware-Entropie (`std::random_device`), für eine extrem schnelle Erzeugung des Schlüsselstroms.
* **Stealth Padding:** Um die Analyse der ursprünglichen Dateigröße durch Dritte zu erschweren, wird jede Datei automatisch mit zufälligem Rauschen (1-100 KB) aufgefüllt.
* **Verschlüsselte Metadaten:** Die Information über die ursprüngliche Dateigröße sowie ein **SHA-256 Integritäts-Hash** werden per XOR-Verknüpfung am Ende der Dateien versteckt. Dies schützt vor Manipulationen während des Transports.
* **Performance-Turbo:** Optimierte Byte-Verarbeitung für blitzschnelles Splitten auch bei sehr großen Dateien im Gigabyte-Bereich.
* **Cross-Plattform:** Reiner C++ Code ohne externe Abhängigkeiten. Perfekt für Linux (CachyOS, Debian etc.) und Windows.

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
