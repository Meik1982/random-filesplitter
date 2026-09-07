// Dieses Programm wurde von Meik Augenblick unter der Lesser GNU General Public License (LGPL) geschrieben.
//
// Random File Splitter (RFS) - Sicheres physisches Dateisplitting via XOR-Stream
//
// Architektur & Kernmerkmale:
// 1. Plattformunabhängiges Entropie-Harvesting (CPU Execution Jitter + std::random_device + ASLR Layout).
// 2. ChaCha20 Stream-Cipher als CSPRNG (kryptografisch sicherer Pseudozufallsgenerator).
// 3. 64-Bit / SIMD-optimierte Block-XOR-Verarbeitung inklusive sicherem Tail-Handling.
// 4. Block-optimierte SHA-256 Integritätsprüfung (Bulk-memcpy-Transformation).
// 5. Stealth-Footer: Beibehaltung des Rauschens von Byte 0 bis zum Ende (keine Magic Bytes am Start).
// 6. Umfassende I/O-Fehlerprüfung (Festplattenvollstand / Schreibabbrüche).
// 7. Schlanke Terminal-Fortschrittsanzeige mit Durchsatzanzeige (MB/s).
// 8. Integrierter Benchmark-Modus (--benchmark).

#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <cstdint>
#include <cstring>
#include <chrono>
#include <random>
#include <algorithm>
#include <iomanip>

// ============================================================================
// 1. SHA-256 Implementierung (Block-optimiert, Endianness-sicher)
// ============================================================================
class SHA256 {
public:
    SHA256() { reset(); }

    void update(const uint8_t* data, size_t len) {
        size_t offset = 0;

        if (m_buffer_len > 0) {
            size_t needed = 64 - m_buffer_len;
            size_t toCopy = std::min(needed, len);
            std::memcpy(m_buffer + m_buffer_len, data, toCopy);
            m_buffer_len += toCopy;
            offset += toCopy;

            if (m_buffer_len == 64) {
                transform(m_buffer);
                m_bit_len += 512;
                m_buffer_len = 0;
            }
        }

        while (offset + 64 <= len) {
            transform(data + offset);
            m_bit_len += 512;
            offset += 64;
        }

        if (offset < len) {
            size_t remaining = len - offset;
            std::memcpy(m_buffer + m_buffer_len, data + offset, remaining);
            m_buffer_len += remaining;
        }
    }

    void final(uint8_t hash[32]) {
        uint64_t i = m_buffer_len;
        if (m_buffer_len < 56) {
            m_buffer[i++] = 0x80;
            while (i < 56) m_buffer[i++] = 0x00;
        } else {
            m_buffer[i++] = 0x80;
            while (i < 64) m_buffer[i++] = 0x00;
            transform(m_buffer);
            std::memset(m_buffer, 0, 56);
        }
        m_bit_len += m_buffer_len * 8;
        m_buffer[63] = static_cast<uint8_t>(m_bit_len);
        m_buffer[62] = static_cast<uint8_t>(m_bit_len >> 8);
        m_buffer[61] = static_cast<uint8_t>(m_bit_len >> 16);
        m_buffer[60] = static_cast<uint8_t>(m_bit_len >> 24);
        m_buffer[59] = static_cast<uint8_t>(m_bit_len >> 32);
        m_buffer[58] = static_cast<uint8_t>(m_bit_len >> 40);
        m_buffer[57] = static_cast<uint8_t>(m_bit_len >> 48);
        m_buffer[56] = static_cast<uint8_t>(m_bit_len >> 56);
        transform(m_buffer);

        for (int j = 0; j < 8; ++j) {
            uint32_t s = m_state[j];
            hash[j * 4]     = static_cast<uint8_t>((s >> 24) & 0xff);
            hash[j * 4 + 1] = static_cast<uint8_t>((s >> 16) & 0xff);
            hash[j * 4 + 2] = static_cast<uint8_t>((s >> 8) & 0xff);
            hash[j * 4 + 3] = static_cast<uint8_t>(s & 0xff);
        }
    }

    void reset() {
        m_state[0] = 0x6a09e667; m_state[1] = 0xbb67ae85; m_state[2] = 0x3c6ef372; m_state[3] = 0xa54ff53a;
        m_state[4] = 0x510e527f; m_state[5] = 0x9b05688c; m_state[6] = 0x1f83d9ab; m_state[7] = 0x5be0cd19;
        m_buffer_len = 0;
        m_bit_len = 0;
    }

private:
    uint32_t m_state[8];
    uint8_t  m_buffer[64];
    uint32_t m_buffer_len;
    uint64_t m_bit_len;

    static inline uint32_t rotr(uint32_t x, uint32_t n) {
        return (x >> n) | (x << (32 - n));
    }
    static inline uint32_t ch(uint32_t x, uint32_t y, uint32_t z) {
        return (x & y) ^ (~x & z);
    }
    static inline uint32_t maj(uint32_t x, uint32_t y, uint32_t z) {
        return (x & y) ^ (x & z) ^ (y & z);
    }

    void transform(const uint8_t block[64]) {
        uint32_t a, b, c, d, e, f, g, h, t1, t2, m[64];
        static const uint32_t k[64] = {
            0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
            0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
            0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
            0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
            0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
            0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
            0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
            0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
        };

        for (int i = 0; i < 16; ++i) {
            m[i] = (static_cast<uint32_t>(block[i * 4]) << 24)
                 | (static_cast<uint32_t>(block[i * 4 + 1]) << 16)
                 | (static_cast<uint32_t>(block[i * 4 + 2]) << 8)
                 | (static_cast<uint32_t>(block[i * 4 + 3]));
        }
        for (int i = 16; i < 64; ++i) {
            m[i] = (rotr(m[i-2],17) ^ rotr(m[i-2],19) ^ (m[i-2] >> 10))
                 + m[i-7]
                 + (rotr(m[i-15],7) ^ rotr(m[i-15],18) ^ (m[i-15] >> 3))
                 + m[i-16];
        }
        a = m_state[0]; b = m_state[1]; c = m_state[2]; d = m_state[3];
        e = m_state[4]; f = m_state[5]; g = m_state[6]; h = m_state[7];
        for (int i = 0; i < 64; ++i) {
            t1 = h + (rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25)) + ch(e, f, g) + k[i] + m[i];
            t2 = (rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22)) + maj(a, b, c);
            h = g; g = f; f = e; e = d + t1;
            d = c; c = b; b = a; a = t1 + t2;
        }
        m_state[0] += a; m_state[1] += b; m_state[2] += c; m_state[3] += d;
        m_state[4] += e; m_state[5] += f; m_state[6] += g; m_state[7] += h;
    }
};

// ============================================================================
// 2. ChaCha20 Stream-Cipher CSPRNG
// ============================================================================
class ChaCha20RNG {
public:
    ChaCha20RNG(const uint8_t key[32], const uint8_t nonce[12], uint32_t initialCounter = 1)
        : m_bufferPos(64) {
        m_state[0] = 0x61707865;
        m_state[1] = 0x3320646e;
        m_state[2] = 0x79622d32;
        m_state[3] = 0x6b206574;

        for (int i = 0; i < 8; ++i) {
            m_state[4 + i] = load32_le(key + i * 4);
        }

        m_state[12] = initialCounter;
        m_state[13] = load32_le(nonce + 0);
        m_state[14] = load32_le(nonce + 4);
        m_state[15] = load32_le(nonce + 8);
    }

    void generateBytes(uint8_t* destination, size_t length) {
        size_t offset = 0;

        if (m_bufferPos < 64) {
            size_t available = 64 - m_bufferPos;
            size_t toCopy = std::min(available, length);
            std::memcpy(destination, m_keystreamBuffer + m_bufferPos, toCopy);
            m_bufferPos += toCopy;
            offset += toCopy;
        }

        while (offset + 64 <= length) {
            generateBlock(destination + offset);
            offset += 64;
        }

        if (offset < length) {
            generateBlock(m_keystreamBuffer);
            size_t remaining = length - offset;
            std::memcpy(destination + offset, m_keystreamBuffer, remaining);
            m_bufferPos = remaining;
        }
    }

    inline uint64_t next_u64() {
        uint64_t val;
        generateBytes(reinterpret_cast<uint8_t*>(&val), sizeof(val));
        return val;
    }

    inline uint8_t next_u8() {
        uint8_t val;
        generateBytes(&val, 1);
        return val;
    }

    inline uint32_t next_range_u32(uint32_t min, uint32_t max) {
        if (min >= max) return min;
        uint32_t range = max - min + 1;
        uint32_t x;
        generateBytes(reinterpret_cast<uint8_t*>(&x), sizeof(x));
        return min + (x % range);
    }

private:
    uint32_t m_state[16];
    uint8_t  m_keystreamBuffer[64];
    size_t   m_bufferPos;

    static inline uint32_t rotl(uint32_t v, int c) {
        return (v << c) | (v >> (32 - c));
    }

    static inline uint32_t load32_le(const uint8_t* p) {
        return static_cast<uint32_t>(p[0])
             | (static_cast<uint32_t>(p[1]) << 8)
             | (static_cast<uint32_t>(p[2]) << 16)
             | (static_cast<uint32_t>(p[3]) << 24);
    }

    static inline void store32_le(uint8_t* p, uint32_t val) {
        p[0] = static_cast<uint8_t>(val);
        p[1] = static_cast<uint8_t>(val >> 8);
        p[2] = static_cast<uint8_t>(val >> 16);
        p[3] = static_cast<uint8_t>(val >> 24);
    }

    static inline void quarterRound(uint32_t& a, uint32_t& b, uint32_t& c, uint32_t& d) {
        a += b; d ^= a; d = rotl(d, 16);
        c += d; b ^= c; b = rotl(b, 12);
        a += b; d ^= a; d = rotl(d, 8);
        c += d; b ^= c; b = rotl(b, 7);
    }

    void generateBlock(uint8_t output[64]) {
        uint32_t x[16];
        std::memcpy(x, m_state, sizeof(x));

        for (int i = 0; i < 10; ++i) {
            quarterRound(x[0], x[4], x[8],  x[12]);
            quarterRound(x[1], x[5], x[9],  x[13]);
            quarterRound(x[2], x[6], x[10], x[14]);
            quarterRound(x[3], x[7], x[11], x[15]);
            quarterRound(x[0], x[5], x[10], x[15]);
            quarterRound(x[1], x[6], x[11], x[12]);
            quarterRound(x[2], x[7], x[8],  x[13]);
            quarterRound(x[3], x[4], x[9],  x[14]);
        }

        for (int i = 0; i < 16; ++i) {
            store32_le(output + i * 4, x[i] + m_state[i]);
        }

        m_state[12]++;
    }
};

// ============================================================================
// 3. Plattformunabhängiger Entropie-Harvester
// ============================================================================
class UniversalEntropyHarvester {
public:
    static void harvestSeed(uint8_t key[32], uint8_t nonce[12]) {
        SHA256 hasher;

        try {
            std::random_device rd;
            for (int i = 0; i < 32; ++i) {
                unsigned int r = rd();
                hasher.update(reinterpret_cast<const uint8_t*>(&r), sizeof(r));
            }
        } catch (...) {
        }

        auto nowWall = std::chrono::system_clock::now().time_since_epoch().count();
        auto nowMono = std::chrono::steady_clock::now().time_since_epoch().count();
        auto nowHigh = std::chrono::high_resolution_clock::now().time_since_epoch().count();
        hasher.update(reinterpret_cast<const uint8_t*>(&nowWall), sizeof(nowWall));
        hasher.update(reinterpret_cast<const uint8_t*>(&nowMono), sizeof(nowMono));
        hasher.update(reinterpret_cast<const uint8_t*>(&nowHigh), sizeof(nowHigh));

        int stackVar = 42;
        int* heapVar = new int(1337);
        void (*funcPtr)(uint8_t*, uint8_t*) = &harvestSeed;
        uintptr_t sAddr = reinterpret_cast<uintptr_t>(&stackVar);
        uintptr_t hAddr = reinterpret_cast<uintptr_t>(heapVar);
        uintptr_t fAddr = reinterpret_cast<uintptr_t>(funcPtr);
        delete heapVar;

        hasher.update(reinterpret_cast<const uint8_t*>(&sAddr), sizeof(sAddr));
        hasher.update(reinterpret_cast<const uint8_t*>(&hAddr), sizeof(hAddr));
        hasher.update(reinterpret_cast<const uint8_t*>(&fAddr), sizeof(fAddr));

        for (int i = 0; i < 2048; ++i) {
            auto t1 = std::chrono::high_resolution_clock::now();
            volatile int dummy = 0;
            for (int j = 0; j < 30; ++j) {
                dummy += (j ^ i);
            }
            auto t2 = std::chrono::high_resolution_clock::now();
            auto diff = (t2 - t1).count();
            int d = dummy;
            hasher.update(reinterpret_cast<const uint8_t*>(&diff), sizeof(diff));
            hasher.update(reinterpret_cast<const uint8_t*>(&d), sizeof(d));
        }

        hasher.final(key);

        hasher.reset();
        hasher.update(key, 32);
        hasher.update(reinterpret_cast<const uint8_t*>("nonce-derivation-rfs"), 20);
        uint8_t nonceHash[32];
        hasher.final(nonceHash);
        std::memcpy(nonce, nonceHash, 12);
    }
};

// ============================================================================
// 4. Hilfsfunktionen für Byte-Serialisierung (Endianness-Sicherheit)
// ============================================================================
static inline void write_u64_le(uint8_t dest[8], uint64_t val) {
    for (int i = 0; i < 8; ++i) {
        dest[i] = static_cast<uint8_t>(val >> (i * 8));
    }
}

static inline uint64_t read_u64_le(const uint8_t src[8]) {
    uint64_t val = 0;
    for (int i = 0; i < 8; ++i) {
        val |= (static_cast<uint64_t>(src[i]) << (i * 8));
    }
    return val;
}

// ============================================================================
// 5. Terminal-Fortschrittsanzeige
// ============================================================================
class ProgressBar {
public:
    ProgressBar(const std::string& taskName, uint64_t totalBytes)
        : m_taskName(taskName), m_totalBytes(totalBytes), m_lastReportedBytes(0) {
        m_startTime = std::chrono::steady_clock::now();
        m_lastUpdateTime = m_startTime;
    }

    void finish(uint64_t currentBytes) {
        update(currentBytes, true);
    }

    void update(uint64_t currentBytes, bool force = false) {
        if (m_finished) return;
        auto now = std::chrono::steady_clock::now();
        auto timeSinceLastUpdate = std::chrono::duration_cast<std::chrono::milliseconds>(now - m_lastUpdateTime).count();

        if (!force && timeSinceLastUpdate < 80 && currentBytes < m_totalBytes) {
            return;
        }
        m_lastUpdateTime = now;

        double progress = (m_totalBytes > 0) ? (static_cast<double>(currentBytes) / m_totalBytes) : 1.0;
        if (progress > 1.0) progress = 1.0;

        auto totalDurationMs = std::chrono::duration_cast<std::chrono::milliseconds>(now - m_startTime).count();
        double speedMBs = 0.0;
        if (totalDurationMs > 50) {
            speedMBs = (static_cast<double>(currentBytes) / (1024.0 * 1024.0)) / (totalDurationMs / 1000.0);
        }

        const int barWidth = 30;
        int pos = static_cast<int>(barWidth * progress);

        std::cout << char(13) << '[' << m_taskName << "] [";
        for (int i = 0; i < barWidth; ++i) {
            if (i < pos) std::cout << '=';
            else if (i == pos) std::cout << '>';
            else std::cout << ' ';
        }
        std::cout << "] " << std::fixed << std::setprecision(1) << (progress * 100.0) << "% ("
                  << speedMBs << " MB/s)    " << std::flush;

        if (force || currentBytes >= m_totalBytes) {
            m_finished = true;
            std::cout << std::endl;
        }
    }

private:
    std::string m_taskName;
    uint64_t m_totalBytes;
    uint64_t m_lastReportedBytes;
    bool m_finished = false;
    std::chrono::steady_clock::time_point m_startTime;
    std::chrono::steady_clock::time_point m_lastUpdateTime;
};

// ============================================================================
// 6. Benchmark-Modus
// ============================================================================
int runBenchmark() {
    std::cout << "\n========================================================\n"
              << " RFS Hardware-Benchmark (64-Bit & SIMD Durchsatz)\n"
              << "========================================================\n\n";

    // 1. Entropie-Harvester Zeitmessung
    auto tStartHarvest = std::chrono::high_resolution_clock::now();
    uint8_t key[32];
    uint8_t nonce[12];
    UniversalEntropyHarvester::harvestSeed(key, nonce);
    auto tEndHarvest = std::chrono::high_resolution_clock::now();
    double harvestMs = std::chrono::duration<double, std::milli>(tEndHarvest - tStartHarvest).count();

    std::cout << " [1/3] Entropie-Harvesting (CPU-Jitter + ASLR + RNG):\n"
              << "       Dauer: " << std::fixed << std::setprecision(2) << harvestMs << " ms\n"
              << "       Status: 256-Bit Key & 96-Bit Nonce erfolgreich extrahiert.\n\n";

    ChaCha20RNG rng(key, nonce);
    SHA256 hasher;

    const size_t BENCH_BUF_SIZE = 16 * 1024 * 1024; // 16 MB Buffer
    const size_t TOTAL_BENCH_BYTES = 256 * 1024 * 1024; // 256 MB Durchlauf
    std::vector<uint8_t> bufferA(BENCH_BUF_SIZE);
    std::vector<uint8_t> bufferB(BENCH_BUF_SIZE);
    std::vector<uint8_t> bufferOut(BENCH_BUF_SIZE);

    // Initiales Füllen
    rng.generateBytes(bufferA.data(), BENCH_BUF_SIZE);

    // 2. ChaCha20 Durchsatzmessung
    auto tStartChaCha = std::chrono::high_resolution_clock::now();
    size_t generated = 0;
    while (generated < TOTAL_BENCH_BYTES) {
        rng.generateBytes(bufferB.data(), BENCH_BUF_SIZE);
        generated += BENCH_BUF_SIZE;
    }
    auto tEndChaCha = std::chrono::high_resolution_clock::now();
    double chachaSeconds = std::chrono::duration<double>(tEndChaCha - tStartChaCha).count();
    double chachaSpeedMB = (TOTAL_BENCH_BYTES / (1024.0 * 1024.0)) / chachaSeconds;

    std::cout << " [2/3] ChaCha20 CSPRNG Durchsatz (256 MB Block-Stream):\n"
              << "       Geschwindigkeit: " << std::fixed << std::setprecision(2)
              << chachaSpeedMB << " MB/s (" << (chachaSpeedMB / 1024.0) << " GB/s)\n\n";

    // 3. 64-Bit Vektor-XOR Durchsatz
    auto tStartXor = std::chrono::high_resolution_clock::now();
    size_t xorProcessed = 0;
    const size_t words = BENCH_BUF_SIZE / 8;
    const uint64_t* pA64 = reinterpret_cast<const uint64_t*>(bufferA.data());
    const uint64_t* pB64 = reinterpret_cast<const uint64_t*>(bufferB.data());
    uint64_t* pOut64 = reinterpret_cast<uint64_t*>(bufferOut.data());

    while (xorProcessed < TOTAL_BENCH_BYTES) {
        for (size_t i = 0; i < words; ++i) {
            pOut64[i] = pA64[i] ^ pB64[i];
        }
        xorProcessed += BENCH_BUF_SIZE;
    }
    auto tEndXor = std::chrono::high_resolution_clock::now();
    double xorSeconds = std::chrono::duration<double>(tEndXor - tStartXor).count();
    double xorSpeedMB = (TOTAL_BENCH_BYTES / (1024.0 * 1024.0)) / xorSeconds;

    std::cout << " [3/3] 64-Bit Fast-Path XOR Durchsatz (256 MB RAM-zu-RAM):\n"
              << "       Geschwindigkeit: " << std::fixed << std::setprecision(2)
              << xorSpeedMB << " MB/s (" << (xorSpeedMB / 1024.0) << " GB/s)\n\n";

    // 4. SHA-256 Block-Update Durchsatz
    auto tStartSha = std::chrono::high_resolution_clock::now();
    size_t shaProcessed = 0;
    while (shaProcessed < TOTAL_BENCH_BYTES) {
        hasher.update(bufferA.data(), BENCH_BUF_SIZE);
        shaProcessed += BENCH_BUF_SIZE;
    }
    uint8_t finalHash[32];
    hasher.final(finalHash);
    auto tEndSha = std::chrono::high_resolution_clock::now();
    double shaSeconds = std::chrono::duration<double>(tEndSha - tStartSha).count();
    double shaSpeedMB = (TOTAL_BENCH_BYTES / (1024.0 * 1024.0)) / shaSeconds;

    std::cout << " [Bonus] SHA-256 Block-Update Hashing:\n"
              << "       Geschwindigkeit: " << std::fixed << std::setprecision(2)
              << shaSpeedMB << " MB/s\n\n";

    std::cout << "Fazit: Ihre Hardware verarbeitet Datenstroeme mit bis zu "
              << std::fixed << std::setprecision(1) << chachaSpeedMB << " MB/s (CSPRNG).\n"
              << "Engpass bei Dateitransfers ist rein das I/O-Limit Ihres Speichermediums.\n\n";
    return 0;
}

// ============================================================================
// 7. Kern-Logik: Verschlüsseln / Splitten
// ============================================================================
void displayHelp() {
    std::cout << "\n========================================================\n"
              << " RFS - Random File Splitter (LGPL)\n"
              << "========================================================\n"
              << " Verwendung:\n"
              << "   Splitten:         rfs <Datei>\n"
              << "   Wiederherstellen: rfs <Datei.rfs1> <Datei.rfs2>\n"
              << "   Benchmark:        rfs --benchmark\n\n";
}

int encryptFile(const std::string& inputFileName) {
    std::ifstream inputFile(inputFileName, std::ios::binary);
    if (!inputFile) {
        std::cerr << "Fehler: Quelldatei '" << inputFileName << "' konnte nicht geoeffnet werden.\n";
        return 1;
    }

    std::string cr1FileName = inputFileName + ".rfs1";
    std::string cr2FileName = inputFileName + ".rfs2";
    std::ofstream cr1File(cr1FileName, std::ios::binary);
    std::ofstream cr2File(cr2FileName, std::ios::binary);

    if (!cr1File || !cr2File) {
        std::cerr << "Fehler: Zieldateien konnten nicht erstellt werden (Schreibrechte pruefen).\n";
        return 1;
    }

    // Dateigröße ermitteln
    inputFile.seekg(0, std::ios::end);
    uint64_t originalSize = inputFile.tellg();
    inputFile.seekg(0, std::ios::beg);

    // Initialisierung des CSPRNG mit geernteter Entropie
    uint8_t masterKey[32];
    uint8_t masterNonce[12];
    UniversalEntropyHarvester::harvestSeed(masterKey, masterNonce);
    ChaCha20RNG rng(masterKey, masterNonce);

    SHA256 hasher;

    // 4 MB Streaming-Buffer für maximale I/O-Effizienz
    const size_t BUFFER_SIZE = 4 * 1024 * 1024;
    std::vector<char> buffer(BUFFER_SIZE);
    std::vector<char> cr1Buf(BUFFER_SIZE);
    std::vector<char> cr2Buf(BUFFER_SIZE);

    ProgressBar progress("Splitting", originalSize);
    uint64_t totalBytesRead = 0;

    while (inputFile) {
        inputFile.read(buffer.data(), BUFFER_SIZE);
        std::streamsize bytesRead = inputFile.gcount();
        if (bytesRead <= 0) break;

        totalBytesRead += bytesRead;

        // SHA-256 Integritätsprüfung im Block-Modus aktualisieren
        hasher.update(reinterpret_cast<const uint8_t*>(buffer.data()), bytesRead);

        // Zufalls-Schlüsselstrom generieren
        rng.generateBytes(reinterpret_cast<uint8_t*>(cr2Buf.data()), bytesRead);

        // 64-Bit Fast-Path XOR
        size_t words = bytesRead / 8;
        const uint64_t* src64 = reinterpret_cast<const uint64_t*>(buffer.data());
        const uint64_t* rnd64 = reinterpret_cast<const uint64_t*>(cr2Buf.data());
        uint64_t* dst64       = reinterpret_cast<uint64_t*>(cr1Buf.data());

        for (size_t i = 0; i < words; ++i) {
            dst64[i] = src64[i] ^ rnd64[i];
        }

        // Tail-Handling für ungerade Bytes (1 bis 7)
        size_t tailOffset = words * 8;
        for (size_t i = tailOffset; i < static_cast<size_t>(bytesRead); ++i) {
            cr1Buf[i] = static_cast<char>(static_cast<uint8_t>(buffer[i]) ^ static_cast<uint8_t>(cr2Buf[i]));
        }

        cr1File.write(cr1Buf.data(), bytesRead);
        cr2File.write(cr2Buf.data(), bytesRead);

        if (!cr1File.good() || !cr2File.good()) {
            std::cerr << "\nFehler: Schreibfehler beim Schreiben der RFS-Dateien (z.B. Datentraeger voll).\n";
            return 1;
        }

        progress.update(totalBytesRead);
    }
    progress.update(totalBytesRead, true);

    // Stealth Padding: 1 KB bis 100 KB zufälliges Rauschen
    uint32_t paddingSize = rng.next_range_u32(1024, 102400);
    std::vector<char> padBuf1(paddingSize);
    std::vector<char> padBuf2(paddingSize);
    rng.generateBytes(reinterpret_cast<uint8_t*>(padBuf1.data()), paddingSize);
    rng.generateBytes(reinterpret_cast<uint8_t*>(padBuf2.data()), paddingSize);
    cr1File.write(padBuf1.data(), paddingSize);
    cr2File.write(padBuf2.data(), paddingSize);

    // Integritäts-Hash (32 Bytes) am Ende verschleiert anhängen
    uint8_t hash[32];
    hasher.final(hash);
    for (int i = 0; i < 32; ++i) {
        uint8_t rnd = rng.next_u8();
        cr1File.put(static_cast<char>(hash[i] ^ rnd));
        cr2File.put(static_cast<char>(rnd));
    }

    // Original-Dateigröße (8 Bytes Little-Endian) verschleiert anhängen
    uint8_t sizeBytes[8];
    write_u64_le(sizeBytes, originalSize);
    for (int i = 0; i < 8; ++i) {
        uint8_t rnd = rng.next_u8();
        cr1File.put(static_cast<char>(sizeBytes[i] ^ rnd));
        cr2File.put(static_cast<char>(rnd));
    }

    cr1File.flush();
    cr2File.flush();
    if (!cr1File.good() || !cr2File.good()) {
        std::cerr << "Fehler: Metadaten konnten nicht vollstaendig auf den Datentraeger geschrieben werden.\n";
        return 1;
    }

    std::cout << "Erfolg: Datei erfolgreich geteilt.\n"
              << "  Teil 1: " << cr1FileName << "\n"
              << "  Teil 2: " << cr2FileName << "\n";
    return 0;
}

// ============================================================================
// 8. Kern-Logik: Entschlüsseln / Rekonstruieren
// ============================================================================
int decryptFile(const std::string& input1, const std::string& input2) {
    std::string fileRfs1 = input1;
    std::string fileRfs2 = input2;
    if (fileRfs1.find(".rfs2") != std::string::npos && fileRfs2.find(".rfs1") != std::string::npos) {
        std::swap(fileRfs1, fileRfs2);
    }

    std::ifstream cr1(fileRfs1, std::ios::binary);
    std::ifstream cr2(fileRfs2, std::ios::binary);
    if (!cr1 || !cr2) {
        std::cerr << "Fehler: Mindestens eine Eingabedatei konnte nicht geoeffnet werden.\n";
        return 1;
    }

    cr1.seekg(0, std::ios::end);
    cr2.seekg(0, std::ios::end);
    uint64_t len1 = cr1.tellg();
    uint64_t len2 = cr2.tellg();

    if (len1 < 40 || len2 < 40) {
        std::cerr << "Fehler: Ungueltige RFS-Dateien (Dateigroesse zu gering fuer Metadaten-Footer).\n";
        return 1;
    }
    if (len1 != len2) {
        std::cerr << "Fehler: Dateigroessen der beiden Teile stimmen nicht ueberein (Beschaedigt oder unvollstaendig).\n";
        return 1;
    }

    std::string outName = fileRfs1;
    if (outName.size() > 5 && outName.substr(outName.size() - 5) == ".rfs1") {
        outName = outName.substr(0, outName.size() - 5);
    } else if (outName.size() > 5 && outName.substr(outName.size() - 5) == ".rfs2") {
        outName = outName.substr(0, outName.size() - 5);
    } else {
        outName += ".restored";
    }

    // 1. Größe aus den letzten 8 Bytes lesen
    cr1.seekg(-8, std::ios::end);
    cr2.seekg(-8, std::ios::end);
    uint8_t sizeBytes[8];
    for (int i = 0; i < 8; ++i) {
        char b1, b2;
        cr1.get(b1); cr2.get(b2);
        sizeBytes[i] = static_cast<uint8_t>(b1) ^ static_cast<uint8_t>(b2);
    }
    uint64_t originalSize = read_u64_le(sizeBytes);

    if (originalSize > len1 - 40) {
        std::cerr << "Fehler: Rekonstruierte Dateigroesse ist unplausibel. Dateien sind beschaedigt.\n";
        return 1;
    }

    // 2. Hash aus dem Footer lesen (32 Bytes vor der Dateigröße)
    cr1.seekg(-40, std::ios::end);
    cr2.seekg(-40, std::ios::end);
    uint8_t expectedHash[32];
    for (int i = 0; i < 32; ++i) {
        char b1, b2;
        cr1.get(b1); cr2.get(b2);
        expectedHash[i] = static_cast<uint8_t>(b1) ^ static_cast<uint8_t>(b2);
    }

    // 3. Nutzlast zusammensetzen und streamen
    std::ofstream out(outName, std::ios::binary);
    if (!out) {
        std::cerr << "Fehler: Ausgabedatei '" << outName << "' kann nicht geschrieben werden.\n";
        return 1;
    }

    cr1.seekg(0, std::ios::beg);
    cr2.seekg(0, std::ios::beg);

    SHA256 hasher;
    const size_t BUFFER_SIZE = 4 * 1024 * 1024;
    std::vector<char> b1(BUFFER_SIZE), b2(BUFFER_SIZE), bOut(BUFFER_SIZE);
    uint64_t processed = 0;

    ProgressBar progress("Restoring", originalSize);

    while (processed < originalSize) {
        uint64_t toRead = std::min(static_cast<uint64_t>(BUFFER_SIZE), originalSize - processed);
        cr1.read(b1.data(), toRead);
        cr2.read(b2.data(), toRead);

        // 64-Bit Fast-Path XOR
        size_t words = toRead / 8;
        const uint64_t* p1_64 = reinterpret_cast<const uint64_t*>(b1.data());
        const uint64_t* p2_64 = reinterpret_cast<const uint64_t*>(b2.data());
        uint64_t* dst64       = reinterpret_cast<uint64_t*>(bOut.data());

        for (size_t i = 0; i < words; ++i) {
            dst64[i] = p1_64[i] ^ p2_64[i];
        }

        // Tail-Handling
        size_t tailOffset = words * 8;
        for (size_t i = tailOffset; i < toRead; ++i) {
            bOut[i] = static_cast<char>(static_cast<uint8_t>(b1[i]) ^ static_cast<uint8_t>(b2[i]));
        }

        hasher.update(reinterpret_cast<const uint8_t*>(bOut.data()), toRead);
        out.write(bOut.data(), toRead);

        if (!out.good()) {
            std::cerr << "\nFehler: Schreibfehler bei der Wiederherstellung (z.B. Datentraeger voll).\n";
            return 1;
        }

        processed += toRead;
        progress.update(processed);
    }
    progress.update(processed, true);

    out.flush();

    // 4. Integritätsprüfung gegen den rekonstruierten SHA-256 Hash
    uint8_t calculatedHash[32];
    hasher.final(calculatedHash);

    if (std::memcmp(calculatedHash, expectedHash, 32) == 0) {
        std::cout << "Erfolg: Datei erfolgreich wiederhergestellt -> " << outName << "\n"
                  << "Integritaet: SHA-256 Hash geprueft und gueltig (OK).\n";
        return 0;
    } else {
        std::cerr << "WARNUNG: Integritaetsfehler! SHA-256 Pruefsumme stimmt nicht ueberein.\n"
                  << "Die Datei ist moeglicherweise beschaedigt oder manipuliert.\n";
        return 2;
    }
}

// ============================================================================
// 9. Programmeinstieg
// ============================================================================
int main(int argc, char* argv[]) {
    if (argc == 2) {
        std::string arg = argv[1];
        if (arg == "-h" || arg == "--help") {
            displayHelp();
            return 0;
        }
        if (arg == "-b" || arg == "--benchmark") {
            return runBenchmark();
        }
        return encryptFile(argv[1]);
    }
    if (argc == 3) {
        return decryptFile(argv[1], argv[2]);
    }

    displayHelp();
    return 0;
}
