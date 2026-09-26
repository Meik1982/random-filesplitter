#include "rfs/types.hpp"
#include "rfs/sha256.hpp"
#include "rfs/chacha20.hpp"
#include "rfs/splitter.hpp"

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

int main() {
    std::cout << "=== RFS2 Test Suite ===\n";
    test_sha256();
    test_chacha20();
    test_endianness();
    test_e2e_lifecycle();
    std::cout << "=== Alle Tests erfolgreich abgeschlossen! ===\n";
    return 0;
}
