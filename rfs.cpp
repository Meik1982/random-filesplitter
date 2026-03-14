// Dieses Programm wurde von Meik Augenblik unter der Lesser GNU General Public License (LGPL) geschrieben.

#include <iostream>
#include <fstream>
#include <string>
#include <random>   // Für die Zufallszahlengenerierung
#include <cstdint>  // Für feste Ganzzahltypen (z. B. uint8_t)

// Funktion zur Anzeige der Hilfestellung
void displayHelp() {
    std::cout << "\n";
    std::cout << " [Hilfe]\n";
    std::cout << " Verschlüsseln:\n";
    std::cout << "   rfs <Datei>\n";
    std::cout << "\n";
    std::cout << " Entschlüsseln:\n";
    std::cout << "   rfs <Datei.rfs1> <Datei.rfs2>\n";
    std::cout << "\n";
}

// Funktion zum Verschlüsseln einer Datei
int encryptFile(const std::string& inputFileName) {
    // Öffne die Eingabedatei im Binärmodus
    std::ifstream inputFile(inputFileName, std::ios::binary);
    if (!inputFile) {
        std::cerr << "Fehler beim Öffnen der Eingabedatei: " << inputFileName << "\n";
        return 1;
    }

    // Erstelle die Namen für die Ausgabedateien
    std::string cr1FileName = inputFileName + ".rfs1";
    std::string cr2FileName = inputFileName + ".rfs2";

    // Öffne die Ausgabedateien im Binärmodus
    std::ofstream cr1File(cr1FileName, std::ios::binary);
    if (!cr1File) {
        std::cerr << "Fehler beim Erstellen der Ausgabedatei: " << cr1FileName << "\n";
        inputFile.close();
        return 1;
    }

    std::ofstream cr2File(cr2FileName, std::ios::binary);
    if (!cr2File) {
        std::cerr << "Fehler beim Erstellen der Ausgabedatei: " << cr2FileName << "\n";
        inputFile.close();
        cr1File.close();
        return 1;
    }

    // Initialisiere den kryptographisch sicheren Zufallszahlengenerator
    std::random_device rd;
    // Verwenden Sie einen Zufallszahlengenerator mit hoher Entropie
    std::uniform_int_distribution<uint8_t> dist(0, 255);

    // Verschlüsselungsprozess
    char byteRead;
    while (inputFile.get(byteRead)) {
        // Generiere ein zufälliges Byte (Schlüsselbyte)
        uint8_t randomByte = dist(rd);

        // Schreibe das verschlüsselte Byte in cr1File
        cr1File.put(static_cast<char>(static_cast<uint8_t>(byteRead) ^ randomByte));

        // Schreibe das Schlüsselbyte in cr2File
        cr2File.put(static_cast<char>(randomByte));
    }

    // Schließe die Dateien
    inputFile.close();
    cr1File.close();
    cr2File.close();

    return 0;
}

// Funktion zum Entschlüsseln einer Datei
int decryptFile(const std::string& cr1FileName, const std::string& cr2FileName) {
    // Öffne die Eingabedateien im Binärmodus
    std::ifstream cr1File(cr1FileName, std::ios::binary);
    if (!cr1File) {
        std::cerr << "Fehler beim Öffnen der Datei: " << cr1FileName << "\n";
        return 1;
    }

    std::ifstream cr2File(cr2FileName, std::ios::binary);
    if (!cr2File) {
        std::cerr << "Fehler beim Öffnen der Datei: " << cr2FileName << "\n";
        cr1File.close();
        return 1;
    }

    // Erstelle den Namen für die Ausgabedatei, indem ".rfs1" entfernt wird
    std::string outputFileName = cr1FileName;
    if (outputFileName.size() > 5 && outputFileName.substr(outputFileName.size() - 5) == ".rfs1") {
        outputFileName.resize(outputFileName.size() - 5);
    } else {
        std::cerr << "Ungültige Dateierweiterung für: " << cr1FileName << "\n";
        cr1File.close();
        cr2File.close();
        return 1;
    }

    // Öffne die Ausgabedatei im Binärmodus
    std::ofstream outputFile(outputFileName, std::ios::binary);
    if (!outputFile) {
        std::cerr << "Fehler beim Erstellen der Ausgabedatei: " << outputFileName << "\n";
        cr1File.close();
        cr2File.close();
        return 1;
    }

    // Entschlüsselungsprozess
    char cr1Byte, cr2Byte;
    while (cr1File.get(cr1Byte) && cr2File.get(cr2Byte)) {
        // XOR der Bytes aus den beiden Dateien, um das Originalbyte wiederherzustellen
        outputFile.put(static_cast<char>(static_cast<uint8_t>(cr1Byte) ^ static_cast<uint8_t>(cr2Byte)));
    }

    // Schließe die Dateien
    outputFile.close();
    cr1File.close();
    cr2File.close();

    return 0;
}

int main(int argc, char* argv[]) {
    if (argc == 1) {
        // Keine Argumente übergeben, zeige Hilfestellung an
        displayHelp();
        return 0;
    } else if (argc == 2) {
        // Ein Argument übergeben, führe Verschlüsselung aus
        std::string inputFileName = argv[1];
        return encryptFile(inputFileName);
    } else if (argc == 3) {
        // Zwei Argumente übergeben, führe Entschlüsselung aus
        std::string cr1FileName = argv[1];
        std::string cr2FileName = argv[2];
        return decryptFile(cr1FileName, cr2FileName);
    } else {
        // Ungültige Anzahl an Argumenten, zeige Hilfestellung an
        displayHelp();
        return 1;
    }
}
