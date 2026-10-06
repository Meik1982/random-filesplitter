#include "rfs/types.hpp"
#include "rfs/sha256.hpp"
#include "rfs/chacha20.hpp"
#include "rfs/splitter.hpp"
#include "rfs/entropy.hpp"

#include <iostream>
#include <cassert>
#include <cstring>
#include <vector>
#include <fstream>
#include <cstdio>

using namespace rfs;

static void test_sha256() {
    std::cout << "[TEST] SHA-256 NIST Test-Vektoren... " << std::flush;

    // Test 1: "" (Empty String)
    {
        SHA256 hasher;
        uint8_t hash[32];
        hasher.final(hash);
        const uint8_t expectedEmpty[32] = {
            0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14,
            0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9, 0x24,
            0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c,
            0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55
        };
        assert(std::memcmp(hash, expectedEmpty, 32) == 0);
    }

    // Test 2: "abc"
    {
        SHA256 hasher;
        hasher.update(reinterpret_cast<const uint8_t*>("abc"), 3);
        uint8_t hash[32];
        hasher.final(hash);
        const uint8_t expectedAbc[32] = {
            0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea,
            0x41, 0x41, 0x40, 0xde, 0x5d, 0xae, 0x22, 0x23,
            0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c,
            0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad
        };
        assert(std::memcmp(hash, expectedAbc, 32) == 0);
    }

    std::cout << "PASSED\n";
}

static void test_chacha20() {
    std::cout << "[TEST] ChaCha20 Deterministische Wiederholbarkeit... " << std::flush;
    uint8_t key[32] = { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16,
                        17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32 };
    uint8_t nonce[12] = { 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66 };

    ChaCha20RNG rng1(key, nonce, 1);
    std::vector<uint8_t> out1(4096);
    rng1.generateBytes(out1.data(), out1.size());

    ChaCha20RNG rng2(key, nonce, 1);
    std::vector<uint8_t> out2(4096);
    rng2.generateBytes(out2.data(), out2.size());

    assert(out1 == out2);
    std::cout << "PASSED\n";
}

static void test_endianness() {
    std::cout << "[TEST] Endianness-Serialisierung... " << std::flush;
    uint64_t original64 = 0x0123456789ABCDEFULL;
    uint8_t buf64[8];
    write_u64_le(buf64, original64);
    uint64_t restored64 = read_u64_le(buf64);
    assert(original64 == restored64);

    uint32_t original32 = 0xFEDCBA98;
    uint8_t buf32[4];
    write_u32_le(buf32, original32);
    uint32_t restored32 = read_u32_le(buf32);
    assert(original32 == restored32);

    std::cout << "PASSED\n";
}

static void test_e2e_lifecycle() {
    std::cout << "[TEST] End-to-End Split, Verify, Restore & Magic-Tag... " << std::flush;

    std::string testPath = "/tmp/rfs_test_e2e.dat";
    std::string customOut = "/tmp/rfs_test_custom.dat";

    // 1. Datei mit Testdaten erzeugen (128 KB)
    {
        std::ofstream f(testPath, std::ios::binary);
        std::vector<char> data(128 * 1024);
        for (size_t i = 0; i < data.size(); ++i) data[i] = static_cast<char>((i * 37 + 11) & 0xFF);
        f.write(data.data(), data.size());
    }

    // 2. Splitten
    SplitOptions sOpts;
    sOpts.inputPath = testPath;
    sOpts.silent = true;
    int res = splitFile(sOpts);
    assert(res == 0);

    // 3. Verify
    RestoreOptions vOpts;
    vOpts.file1 = testPath + ".rfs1";
    vOpts.file2 = testPath + ".rfs2";
    vOpts.verifyOnly = true;
    vOpts.silent = true;
    res = restoreOrVerifyFile(vOpts);
    assert(res == 0);

    // 4. Restore auf Custom Path
    RestoreOptions rOpts;
    rOpts.file1 = testPath + ".rfs1";
    rOpts.file2 = testPath + ".rfs2";
    rOpts.outputPath = customOut;
    rOpts.force = true;
    rOpts.silent = true;
    res = restoreOrVerifyFile(rOpts);
    assert(res == 0);

    // 5. Bit-Genauer Inhaltsvergleich
    {
        std::ifstream orig(testPath, std::ios::binary);
        std::ifstream rest(customOut, std::ios::binary);
        orig.seekg(0, std::ios::end);
        rest.seekg(0, std::ios::end);
        assert(orig.tellg() == rest.tellg());

        orig.seekg(0, std::ios::beg);
        rest.seekg(0, std::ios::beg);
        std::vector<char> d1(orig.tellg()), d2(rest.tellg());
        orig.read(d1.data(), d1.size());
        rest.read(d2.data(), d2.size());
        assert(d1 == d2);
    }

    // 6. Magic Tag Validierungstest: Falsche Datei übergeben
    {
        // Fall A: Ungleiche Größen
        RestoreOptions badOpts1;
        badOpts1.file1 = testPath + ".rfs1";
        badOpts1.file2 = testPath; // Originaldatei statt .rfs2
        badOpts1.verifyOnly = true;
        badOpts1.silent = true;
        int badRes1 = restoreOrVerifyFile(badOpts1);
        assert(badRes1 != 0);

        // Fall B: Gleiche Größen (z.B. zwei .rfs1 Kopien), aber XOR ergibt keinen RFS2-Magic-Tag
        RestoreOptions badOpts2;
        badOpts2.file1 = testPath + ".rfs1";
        badOpts2.file2 = testPath + ".rfs1"; // dieselbe Datei mit sich selbst ge-XORt ergibt 0x00 statt "RFS2"
        badOpts2.verifyOnly = true;
        badOpts2.silent = true;
        int badRes2 = restoreOrVerifyFile(badOpts2);
        assert(badRes2 != 0);
    }

    // Aufräumen
    std::remove(testPath.c_str());
    std::remove((testPath + ".rfs1").c_str());
    std::remove((testPath + ".rfs2").c_str());
    std::remove(customOut.c_str());

    std::cout << "PASSED\n";
}

void test_file_entropy() {
    std::cout << "[TEST] Kryptoanalytische Datei-Entropieanalyse... " << std::flush;
    std::string highEntropyFile = "/tmp/rfs_test_high_entropy.bin";
    std::string lowEntropyFile = "/tmp/rfs_test_low_entropy.txt";

    // Datei mit hoher Entropie (Zufallsdaten)
    {
        std::ofstream out(highEntropyFile, std::ios::binary);
        uint8_t k[32] = {1, 2, 3, 4};
        uint8_t n[12] = {5, 6, 7, 8};
        ChaCha20RNG rng(k, n);
        std::vector<uint8_t> buf(65536);
        rng.generateBytes(buf.data(), buf.size());
        out.write(reinterpret_cast<const char*>(buf.data()), buf.size());
    }

    // Datei mit niedriger Entropie (Wiederholender Text)
    {
        std::ofstream out(lowEntropyFile);
        for (int i = 0; i < 5000; ++i) {
            out << "Dies ist ein unverschluesselter repetitiver Klartext mit geringer Entropie.\n";
        }
    }

    int resHigh = analyzeFileEntropy(highEntropyFile);
    assert(resHigh == 0);

    int resLow = analyzeFileEntropy(lowEntropyFile);
    assert(resLow == 0);

    std::remove(highEntropyFile.c_str());
    std::remove(lowEntropyFile.c_str());
    std::cout << "PASSED\n";
}

void test_large_file_pipeline() {
    std::cout << "[TEST] Multi-Chunk Double-Buffering Pipeline (5 MB)... " << std::flush;
    std::string pathOrig = "/tmp/rfs_test_large.dat";
    std::string pathRest = "/tmp/rfs_test_large.restored";

    // 5 MB Datei erzeugen
    const size_t LARGE_SIZE = 5 * 1024 * 1024;
    {
        std::ofstream f(pathOrig, std::ios::binary);
        std::vector<char> chunk(65536);
        for (size_t i = 0; i < chunk.size(); ++i) chunk[i] = static_cast<char>((i * 17 + 3) & 0xFF);
        size_t written = 0;
        while (written < LARGE_SIZE) {
            size_t toWrite = std::min(chunk.size(), LARGE_SIZE - written);
            f.write(chunk.data(), toWrite);
            written += toWrite;
        }
    }

    SplitOptions sOpts;
    sOpts.inputPath = pathOrig;
    sOpts.silent = true;
    assert(splitFile(sOpts) == 0);

    RestoreOptions rOpts;
    rOpts.file1 = pathOrig + ".rfs1";
    rOpts.file2 = pathOrig + ".rfs2";
    rOpts.outputPath = pathRest;
    rOpts.force = true;
    rOpts.silent = true;
    assert(restoreOrVerifyFile(rOpts) == 0);

    // Vergleich
    {
        std::ifstream f1(pathOrig, std::ios::binary);
        std::ifstream f2(pathRest, std::ios::binary);
        f1.seekg(0, std::ios::end);
        f2.seekg(0, std::ios::end);
        assert(f1.tellg() == f2.tellg());
        assert(static_cast<size_t>(f1.tellg()) == LARGE_SIZE);
    }

    std::remove(pathOrig.c_str());
    std::remove((pathOrig + ".rfs1").c_str());
    std::remove((pathOrig + ".rfs2").c_str());
    std::remove(pathRest.c_str());
    std::cout << "PASSED\n";
}

void test_tamper_detection() {
    std::cout << "[TEST] Integritaetsprüfung & Bit-Flip Tamper Detection... " << std::flush;
    std::string pathOrig = "/tmp/rfs_test_tamper.dat";
    std::string pathRest = "/tmp/rfs_test_tamper.restored";

    {
        std::ofstream f(pathOrig, std::ios::binary);
        std::vector<char> buf(4096, 'A');
        f.write(buf.data(), buf.size());
    }

    SplitOptions sOpts;
    sOpts.inputPath = pathOrig;
    sOpts.silent = true;
    assert(splitFile(sOpts) == 0);

    // Byte 10 in .rfs1 manipulieren (Bit-Flip)
    {
        std::fstream f1(pathOrig + ".rfs1", std::ios::in | std::ios::out | std::ios::binary);
        f1.seekp(10, std::ios::beg);
        char byte;
        f1.get(byte);
        f1.seekp(10, std::ios::beg);
        f1.put(static_cast<char>(byte ^ 0xFF));
    }

    // Restore muss wegen SHA-256 Checksummenfehler abbrechen (Exit Code 2)
    RestoreOptions rOpts;
    rOpts.file1 = pathOrig + ".rfs1";
    rOpts.file2 = pathOrig + ".rfs2";
    rOpts.outputPath = pathRest;
    rOpts.force = true;
    rOpts.silent = true;
    int res = restoreOrVerifyFile(rOpts);
    assert(res == 2); // Hash mismatch detected!

    std::remove(pathOrig.c_str());
    std::remove((pathOrig + ".rfs1").c_str());
    std::remove((pathOrig + ".rfs2").c_str());
    std::remove(pathRest.c_str());
    std::cout << "PASSED\n";
}

void test_variable_block_sizes() {
    std::cout << "[TEST] Variable Blockgrößen (64K, 1M, 16M) & Suffix-Parser... " << std::flush;

    // 1. Suffix-Parser Validierung
    size_t sz = 0;
    assert(parseBlockSize("64K", sz) && sz == 64 * 1024);
    assert(parseBlockSize("64k", sz) && sz == 64 * 1024);
    assert(parseBlockSize("1M", sz) && sz == 1024 * 1024);
    assert(parseBlockSize("4M", sz) && sz == 4 * 1024 * 1024);
    assert(parseBlockSize("16M", sz) && sz == 16 * 1024 * 1024);
    assert(parseBlockSize("256M", sz) && sz == 256 * 1024 * 1024);
    assert(!parseBlockSize("32K", sz)); // Unter Minimum (64K)
    assert(!parseBlockSize("512M", sz)); // Über Maximum (256M)
    assert(!parseBlockSize("invalid", sz));
    assert(!parseBlockSize("", sz));

    // 2. E2E mit 64 KiB Blockgröße
    std::string pathOrig = "/tmp/rfs_test_var_blocks.dat";
    std::string pathRest = "/tmp/rfs_test_var_blocks.restored";

    {
        std::ofstream f(pathOrig, std::ios::binary);
        std::vector<char> data(512 * 1024);
        for (size_t i = 0; i < data.size(); ++i) data[i] = static_cast<char>((i * 13 + 7) & 0xFF);
        f.write(data.data(), data.size());
    }

    SplitOptions sOpts;
    sOpts.inputPath = pathOrig;
    sOpts.blockSize = 64 * 1024; // 64K
    sOpts.silent = true;
    assert(splitFile(sOpts) == 0);

    RestoreOptions rOpts;
    rOpts.file1 = pathOrig + ".rfs1";
    rOpts.file2 = pathOrig + ".rfs2";
    rOpts.outputPath = pathRest;
    rOpts.blockSize = 128 * 1024; // Asymmetrische Restore-Blockgröße
    rOpts.force = true;
    rOpts.silent = true;
    assert(restoreOrVerifyFile(rOpts) == 0);

    {
        std::ifstream f1(pathOrig, std::ios::binary);
        std::ifstream f2(pathRest, std::ios::binary);
        f1.seekg(0, std::ios::end);
        f2.seekg(0, std::ios::end);
        assert(f1.tellg() == f2.tellg());
        std::vector<char> d1(f1.tellg()), d2(f2.tellg());
        f1.seekg(0, std::ios::beg);
        f2.seekg(0, std::ios::beg);
        f1.read(d1.data(), d1.size());
        f2.read(d2.data(), d2.size());
        assert(d1 == d2);
    }

    std::remove(pathOrig.c_str());
    std::remove((pathOrig + ".rfs1").c_str());
    std::remove((pathOrig + ".rfs2").c_str());
    std::remove(pathRest.c_str());
    std::cout << "PASSED\n";
}

void test_entropy_harvesting_freshness() {
    std::cout << "[TEST] Gehärtetes Entropie-Harvesting (OS CSPRNG + Jitter)... " << std::flush;
    uint8_t k1[32], n1[12];
    uint8_t k2[32], n2[12];

    UniversalEntropyHarvester::harvestSeed(k1, n1);
    UniversalEntropyHarvester::harvestSeed(k2, n2);

    // Beide Aufrufe müssen völlig unabhängige Schlüssel und Nonces erzeugen
    assert(std::memcmp(k1, k2, 32) != 0);
    assert(std::memcmp(n1, n2, 12) != 0);

    // Nicht-Trivialität (nicht nur Nullen)
    uint8_t zeroKey[32] = {0};
    uint8_t zeroNonce[12] = {0};
    assert(std::memcmp(k1, zeroKey, 32) != 0);
    assert(std::memcmp(n1, zeroNonce, 12) != 0);

    secure_wipe_memory(k1, sizeof(k1));
    secure_wipe_memory(n1, sizeof(n1));
    secure_wipe_memory(k2, sizeof(k2));
    secure_wipe_memory(n2, sizeof(n2));
    std::cout << "PASSED\n";
}

int main() {
    std::cout << "=== RFS2 Test Suite ===\n";
    test_sha256();
    test_chacha20();
    test_endianness();
    test_e2e_lifecycle();
    test_large_file_pipeline();
    test_variable_block_sizes();
    test_tamper_detection();
    test_entropy_harvesting_freshness();
    test_file_entropy();
    std::cout << "=== Alle Tests erfolgreich abgeschlossen! ===\n";
    return 0;
}
