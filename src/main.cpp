#include "rfs/splitter.hpp"
#include "rfs/entropy.hpp"
#include <iostream>
#include <string>
#include <vector>

int main(int argc, char* argv[]) {
    if (argc < 2) {
        rfs::displayHelp();
        return 1;
    }

    std::string firstArg = argv[1];
    if (firstArg == "-h" || firstArg == "--help") {
        rfs::displayHelp();
        return 0;
    }
    if (firstArg == "-V" || firstArg == "--version") {
        rfs::displayVersion();
        return 0;
    }
    if (firstArg == "-b" || firstArg == "--benchmark") {
        return rfs::runBenchmark();
    }
    if (firstArg == "-e" || firstArg == "--entropy" || firstArg == "--entropy-test") {
        return rfs::runEntropyTest();
    }
    if (firstArg == "-a" || firstArg == "--analyze" || firstArg == "--file-entropy") {
        if (argc < 3) {
            std::cerr << "Fehler: Option " << firstArg << " erfordert einen Dateipfad.\n";
            std::cerr << "Verwendung: rfs -a <Datei>\n";
            return 1;
        }
        return rfs::analyzeFileEntropy(argv[2]);
    }

    // Flag-Parsing
    bool verifyOnly = false;
    bool force = false;
    bool silent = false;
    size_t blockSize = rfs::DEFAULT_BLOCK_SIZE;
    std::string outputPath;
    std::vector<std::string> positional;

    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "-v" || arg == "--verify" || arg == "--check") {
            verifyOnly = true;
        } else if (arg == "-B" || arg == "--block-size") {
            if (i + 1 < argc) {
                size_t parsedSize = 0;
                if (!rfs::parseBlockSize(argv[++i], parsedSize)) {
                    std::cerr << "Fehler: Ungueltige Blockgroesse '" << argv[i] << "'.\n"
                              << "Erlaubter Bereich: 64K bis 256M (z.B. 64K, 1M, 4M, 16M).\n";
                    return 1;
                }
                blockSize = parsedSize;
            } else {
                std::cerr << "Fehler: Option " << arg << " erfordert eine Groessenangabe.\n";
                return 1;
            }
        } else if (arg == "-a" || arg == "--analyze" || arg == "--file-entropy") {
            if (i + 1 < argc) {
                return rfs::analyzeFileEntropy(argv[++i]);
            } else {
                std::cerr << "Fehler: Option " << arg << " erfordert einen Dateipfad.\n";
                return 1;
            }
        } else if (arg == "-f" || arg == "--force") {
            force = true;
        } else if (arg == "-s" || arg == "--silent") {
            silent = true;
        } else if (arg == "-o" || arg == "--output") {
            if (i + 1 < argc) {
                outputPath = argv[++i];
            } else {
                std::cerr << "Fehler: Option " << arg << " erfordert einen Dateipfad.\n";
                return 1;
            }
        } else if (arg == "-h" || arg == "--help") {
            rfs::displayHelp();
            return 0;
        } else if (arg == "-V" || arg == "--version") {
            rfs::displayVersion();
            return 0;
        } else if (arg.size() > 0 && arg[0] == '-') {
            std::cerr << "Fehler: Unbekannte Option '" << arg << "'. Verwenden Sie --help.\n";
            return 1;
        } else {
            positional.push_back(arg);
        }
    }

    if (positional.size() == 1) {
        if (verifyOnly) {
            std::cerr << "Fehler: Integritaetstest benoetigt beide Teil-Dateien (.rfs1 und .rfs2).\n";
            return 1;
        }
        rfs::SplitOptions opts;
        opts.inputPath = positional[0];
        opts.blockSize = blockSize;
        opts.silent = silent;
        return rfs::splitFile(opts);
    }

    if (positional.size() == 2) {
        rfs::RestoreOptions opts;
        opts.file1 = positional[0];
        opts.file2 = positional[1];
        opts.outputPath = outputPath;
        opts.blockSize = blockSize;
        opts.verifyOnly = verifyOnly;
        opts.force = force;
        opts.silent = silent;
        return rfs::restoreOrVerifyFile(opts);
    }

    std::cerr << "Fehler: Ungueltige Anzahl an Argumenten. Verwenden Sie --help fuer die Syntax.\n";
    return 1;
}
