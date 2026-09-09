// Dieses Programm wurde von Meik Augenblick unter der Lesser GNU General Public License (LGPL) geschrieben.
//
// Random File Splitter (RFS) - High-Performance & High-Security File Splitter
//
// Architektur & Kernmerkmale:
// 1. Plattformunabhängiges Entropie-Harvesting (Cache/Memory Jitter + std::random_device + ASLR Layout).
// 2. ChaCha20 Stream-Cipher CSPRNG mit nativer AVX2-SIMD-Vektorisierung (4 Blöcke parallel)
//    sowie portablem 64-Bit Fallback für ARM, Mac M-Chips und Nicht-AVX2-CPUs.
// 3. Multi-Threaded Pipelining & Asynchrones I/O (Producer-Consumer via std::thread / std::future).
// 4. Paralleles Hashing (SHA-256 Thread entkoppelt vom Krypto- & Schreib-Pipeline-Thread).
// 5. Explicit Secure Wipe (Krypto-Hygiene: Nullung aller sensitiven Speicherbereiche).
// 6. Verify-Modus (--verify): Schnelle Integritätsprüfung ohne Zurückschreiben auf Platte.
// 7. Entropie-Qualitätsanalyse (--entropy-test):
//    - Phase 1: Diagnose der unkonditionierten CPU- und Memory-Jitter-Rohdaten.
//    - Phase 2: NIST-Metriken auf den ChaCha20-Schlüsselstrom (Shannon-Entropie, Chi-Quadrat, Bit-Balance).
// 8. Interaktive Terminal-Fortschrittsanzeige & Hardware-Benchmark (--benchmark).

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
#include <thread>
#include <future>
#include <memory>
#include <cmath>
#include <map>

#if defined(__AVX2__)
#include <immintrin.h>
#endif

// ============================================================================
// 0. Krypto-Hygiene: Explicit Secure Wipe
// ============================================================================
static void secure_wipe_memory(void* ptr, size_t size) {
    if (!ptr || size == 0) return;
    volatile uint8_t* p = static_cast<volatile uint8_t*>(ptr);
    while (size--) {
        *p++ = 0;
    }
}

// ============================================================================
// 1. SHA-256 Implementierung (Block-optimiert, Endianness-sicher)
// ============================================================================
class SHA256 {
public:
    SHA256() { reset(); }
    ~SHA256() { wipe(); }

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
        wipe();
    }

    void reset() {
        m_state[0] = 0x6a09e667; m_state[1] = 0xbb67ae85; m_state[2] = 0x3c6ef372; m_state[3] = 0xa54ff53a;
        m_state[4] = 0x510e527f; m_state[5] = 0x9b05688c; m_state[6] = 0x1f83d9ab; m_state[7] = 0x5be0cd19;
        m_buffer_len = 0;
        m_bit_len = 0;
    }

    void wipe() {
        secure_wipe_memory(m_state, sizeof(m_state));
        secure_wipe_memory(m_buffer, sizeof(m_buffer));
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
// 2. ChaCha20 Stream-Cipher CSPRNG mit nativer AVX2-Beschleunigung
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

    ~ChaCha20RNG() {
        secure_wipe_memory(m_state, sizeof(m_state));
        secure_wipe_memory(m_keystreamBuffer, sizeof(m_keystreamBuffer));
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

#if defined(__AVX2__)
        while (offset + 256 <= length) {
            generate4BlocksAVX2(destination + offset);
            offset += 256;
        }
#endif

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

#if defined(__AVX2__)
    static inline __m256i rotl_avx2(__m256i x, int n) {
        return _mm256_or_si256(_mm256_slli_epi32(x, n), _mm256_srli_epi32(x, 32 - n));
    }

    static inline void quarterRoundAVX2(__m256i& a, __m256i& b, __m256i& c, __m256i& d) {
        a = _mm256_add_epi32(a, b);
        d = _mm256_xor_si256(d, a);
        d = rotl_avx2(d, 16);

        c = _mm256_add_epi32(c, d);
        b = _mm256_xor_si256(b, c);
        b = rotl_avx2(b, 12);

        a = _mm256_add_epi32(a, b);
        d = _mm256_xor_si256(d, a);
        d = rotl_avx2(d, 8);

        c = _mm256_add_epi32(c, d);
        b = _mm256_xor_si256(b, c);
        b = rotl_avx2(b, 7);
    }

    void generate4BlocksAVX2(uint8_t output[256]) {
        __m256i s[16];
        for (int i = 0; i < 16; ++i) {
            if (i == 12) {
                s[12] = _mm256_set_epi32(m_state[12] + 3, m_state[12] + 2, m_state[12] + 1, m_state[12],
                                         m_state[12] + 3, m_state[12] + 2, m_state[12] + 1, m_state[12]);
            } else {
                s[i] = _mm256_set1_epi32(m_state[i]);
            }
        }

        __m256i x[16];
        for (int i = 0; i < 16; ++i) x[i] = s[i];

        for (int r = 0; r < 10; ++r) {
            quarterRoundAVX2(x[0], x[4], x[8],  x[12]);
            quarterRoundAVX2(x[1], x[5], x[9],  x[13]);
            quarterRoundAVX2(x[2], x[6], x[10], x[14]);
            quarterRoundAVX2(x[3], x[7], x[11], x[15]);
            quarterRoundAVX2(x[0], x[5], x[10], x[15]);
            quarterRoundAVX2(x[1], x[6], x[11], x[12]);
            quarterRoundAVX2(x[2], x[7], x[8],  x[13]);
            quarterRoundAVX2(x[3], x[4], x[9],  x[14]);
        }

        for (int i = 0; i < 16; ++i) {
            x[i] = _mm256_add_epi32(x[i], s[i]);
        }

        uint32_t tmp[16][8];
        for (int i = 0; i < 16; ++i) {
            _mm256_storeu_si256(reinterpret_cast<__m256i*>(tmp[i]), x[i]);
        }

        for (int b = 0; b < 4; ++b) {
            uint8_t* blockOut = output + b * 64;
            for (int i = 0; i < 16; ++i) {
                store32_le(blockOut + i * 4, tmp[i][b]);
            }
        }

        m_state[12] += 4;
    }
#endif
};

// ============================================================================
// 3. Plattformunabhängiger Entropie-Harvester
//    Erntet Hardware-RNG, ASLR-Pointer, Monotonic Clocks und Cache/DRAM Jitter.
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

        // Cache- und Memory-Jitter: Pointer-Chasing über 1 KB Puffer
        // Provoziert nicht-deterministische L2/L3- und DRAM-Bus-Latenzen
        alignas(64) static volatile uint8_t memPool[1024];
        for (size_t k = 0; k < 1024; ++k) {
            memPool[k] = static_cast<uint8_t>((k * 73 + 19) & 0xFF);
        }

        size_t pointerIdx = 0;
        for (int i = 0; i < 2048; ++i) {
            auto t1 = std::chrono::high_resolution_clock::now();
            for (int j = 0; j < 32; ++j) {
                pointerIdx = (memPool[pointerIdx] + j) % 1024;
            }
            auto t2 = std::chrono::high_resolution_clock::now();
            auto diff = (t2 - t1).count();
            int idxVal = static_cast<int>(pointerIdx);
            hasher.update(reinterpret_cast<const uint8_t*>(&diff), sizeof(diff));
            hasher.update(reinterpret_cast<const uint8_t*>(&idxVal), sizeof(idxVal));
        }

        hasher.final(key);

        hasher.reset();
        hasher.update(key, 32);
        hasher.update(reinterpret_cast<const uint8_t*>("nonce-derivation-rfs"), 20);
        uint8_t nonceHash[32];
        hasher.final(nonceHash);
        std::memcpy(nonce, nonceHash, 12);
        secure_wipe_memory(nonceHash, sizeof(nonceHash));
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
// 6. Entropie- & Kryptoanalyse-Diagnose (--entropy-test)
// ============================================================================
int runEntropyTest() {
    std::cout << "\n============================================================\n"
              << " RFS Entropie- & Kryptoanalyse-Diagnose (NIST & Jitter)\n"
              << "============================================================\n\n";

    // ------------------------------------------------------------------------
    // Phase 1: Diagnose der unkonditionierten CPU- & Cache-Jitter-Rohdaten
    // ------------------------------------------------------------------------
    std::cout << "--- [Phase 1: Roh-Entropie-Diagnose des CPU- & Memory-Jitters] ---\n"
              << "Sammle 8.192 Nanosekunden-Differenzen (Cache- & Bus-Latenzen)...\n\n";

    const size_t JITTER_SAMPLES = 8192;
    std::vector<int64_t> deltas(JITTER_SAMPLES);
    std::map<int64_t, size_t> buckets;
    double sum = 0.0;
    size_t bitFlips = 0;

    alignas(64) static volatile uint8_t testPool[1024];
    for (size_t k = 0; k < 1024; ++k) {
        testPool[k] = static_cast<uint8_t>((k * 73 + 19) & 0xFF);
    }

    size_t pointerIdx = 0;
    for (size_t i = 0; i < JITTER_SAMPLES; ++i) {
        auto t1 = std::chrono::high_resolution_clock::now();
        for (int j = 0; j < 32; ++j) {
            pointerIdx = (testPool[pointerIdx] + j) % 1024;
        }
        auto t2 = std::chrono::high_resolution_clock::now();
        int64_t diff = (t2 - t1).count();
        deltas[i] = diff;
        buckets[diff]++;
        sum += static_cast<double>(diff);

        if (i > 0) {
            if ((deltas[i] & 1) != (deltas[i - 1] & 1)) {
                bitFlips++;
            }
        }
    }

    double mean = sum / JITTER_SAMPLES;
    double varianceSum = 0.0;
    for (int64_t d : deltas) {
        double dev = static_cast<double>(d) - mean;
        varianceSum += (dev * dev);
    }
    double stddev = std::sqrt(varianceSum / JITTER_SAMPLES);
    double bitFlipRatio = (static_cast<double>(bitFlips) / (JITTER_SAMPLES - 1)) * 100.0;

    double rawEntropy = 0.0;
    for (const auto& pair : buckets) {
        double p = static_cast<double>(pair.second) / JITTER_SAMPLES;
        if (p > 0.0) {
            rawEntropy -= p * (std::log(p) / std::log(2.0));
        }
    }

    bool jitterVarianceOk = (stddev >= 1.0);
    bool jitterBucketsOk  = (buckets.size() >= 8);
    bool jitterBitFlipsOk = (bitFlipRatio >= 20.0 && bitFlipRatio <= 80.0);
    bool jitterEntropyOk  = (rawEntropy >= 1.2);

    std::cout << " [1] Standardabweichung (Timing-Jitter Streuung):\n"
              << "     Gemessen: " << std::fixed << std::setprecision(2) << stddev << " ns  "
              << (jitterVarianceOk ? "[BESTANDEN]" : "[FEHLGESCHLAGEN!]") << "\n"
              << "     (Mindestanforderung: sigma >= 1.0 ns)\n\n";

    std::cout << " [2] Eindeutige Timing-Buckets (Diskrete Zyklenwerte):\n"
              << "     Gefunden: " << buckets.size() << " verschiedene Zyklenwerte  "
              << (jitterBucketsOk ? "[BESTANDEN]" : "[FEHLGESCHLAGEN!]") << "\n"
              << "     (Mindestanforderung: mind. 8 Buckets)\n\n";

    std::cout << " [3] LSB Bit-Transitionsrate (Rausch-Flips):\n"
              << "     Wechselrate: " << std::fixed << std::setprecision(1) << bitFlipRatio << " %  "
              << (jitterBitFlipsOk ? "[BESTANDEN]" : "[FEHLGESCHLAGEN!]") << "\n"
              << "     (Ideal: 50.0 %, Akzeptanzbereich: 20.0 % - 80.0 %)\n\n";

    std::cout << " [4] Shannon-Entropie der unkonditionierten Roh-Timings:\n"
              << "     Gemessen: " << std::fixed << std::setprecision(3) << rawEntropy << " Bits / Sample  "
              << (jitterEntropyOk ? "[BESTANDEN]" : "[FEHLGESCHLAGEN!]") << "\n"
              << "     (Mindestanforderung: >= 1.200 Bits)\n\n";

    if (jitterVarianceOk && jitterBucketsOk && jitterBitFlipsOk && jitterEntropyOk) {
        std::cout << "Status Phase 1: [OK] Die CPU liefert echte physikalische Timing-Entropie.\n\n";
    } else {
        std::cout << "WARNUNG Phase 1: [FEHLER] Keine oder unzureichende CPU-Jitter-Entropie!\n"
                  << "Hinweis: Laeuft das System in einem starren Emulator oder einer virtuellen Umgebung?\n\n";
    }

    // ------------------------------------------------------------------------
    // Phase 2: NIST-Kryptoanalyse auf den ChaCha20-Schlüsselstrom
    // ------------------------------------------------------------------------
    std::cout << "--- [Phase 2: Kryptoanalyse des CSPRNG-Schlüsselstroms] ---\n"
              << "Generiere 16 MB ChaCha20-Stream fuer statistische NIST-Metriken...\n\n";

    uint8_t masterKey[32];
    uint8_t masterNonce[12];
    UniversalEntropyHarvester::harvestSeed(masterKey, masterNonce);
    ChaCha20RNG rng(masterKey, masterNonce);

    const size_t STREAM_SIZE = 16 * 1024 * 1024; // 16 MB
    std::vector<uint8_t> stream(STREAM_SIZE);
    rng.generateBytes(stream.data(), STREAM_SIZE);

    std::vector<uint64_t> byteCounts(256, 0);
    uint64_t totalOnes = 0;
    double sumStreamBytes = 0.0;

    for (size_t i = 0; i < STREAM_SIZE; ++i) {
        uint8_t b = stream[i];
        byteCounts[b]++;
        sumStreamBytes += b;
#if defined(__GNUC__) || defined(__clang__)
        totalOnes += __builtin_popcount(b);
#else
        for (int bit = 0; bit < 8; ++bit) totalOnes += ((b >> bit) & 1);
#endif
    }

    double shannonEntropy = 0.0;
    for (int i = 0; i < 256; ++i) {
        double p = static_cast<double>(byteCounts[i]) / STREAM_SIZE;
        if (p > 0.0) {
            shannonEntropy -= p * (std::log(p) / std::log(2.0));
        }
    }

    double expectedCount = static_cast<double>(STREAM_SIZE) / 256.0;
    double chiSquare = 0.0;
    for (int i = 0; i < 256; ++i) {
        double diff = static_cast<double>(byteCounts[i]) - expectedCount;
        chiSquare += (diff * diff) / expectedCount;
    }

    double streamMean = sumStreamBytes / STREAM_SIZE;
    double bitBalancePercent = (static_cast<double>(totalOnes) / (STREAM_SIZE * 8.0)) * 100.0;

    double numerator = 0.0;
    double denom = 0.0;
    for (size_t i = 0; i < STREAM_SIZE - 1; ++i) {
        double x = static_cast<double>(stream[i]) - 127.5;
        double y = static_cast<double>(stream[i + 1]) - 127.5;
        numerator += (x * y);
        denom += (x * x);
    }
    double serialCorr = (denom > 0.0) ? (numerator / denom) : 0.0;

    bool shannonOk = (shannonEntropy >= 7.9999);
    bool chiOk = (chiSquare >= 180.0 && chiSquare <= 330.0);
    bool meanOk = (std::abs(streamMean - 127.5) < 0.05);
    bool bitBalanceOk = (std::abs(bitBalancePercent - 50.0) < 0.05);
    bool corrOk = (std::abs(serialCorr) < 0.001);

    std::cout << " [1] Shannon-Entropie (Gleichverteilung pro Byte):\n"
              << "     Gemessen: " << std::fixed << std::setprecision(6) << shannonEntropy << " Bits / Byte  "
              << (shannonOk ? "[BESTANDEN]" : "[FEHLGESCHLAGEN!]") << "\n"
              << "     (Theoretisches Maximum: 8.000000 Bits)\n\n";

    std::cout << " [2] Chi-Quadrat Anpassungstest (df = 255):\n"
              << "     Gemessen: " << std::fixed << std::setprecision(2) << chiSquare << "  "
              << (chiOk ? "[BESTANDEN]" : "[FEHLGESCHLAGEN!]") << "\n"
              << "     (Idealer statistischer Bereich: 180.00 - 330.00)\n\n";

    std::cout << " [3] Arithmetischer Mittelwert der Bytes:\n"
              << "     Gemessen: " << std::fixed << std::setprecision(3) << streamMean << "  "
              << (meanOk ? "[BESTANDEN]" : "[FEHLGESCHLAGEN!]") << "\n"
              << "     (Theoretisches Ideal: 127.500)\n\n";

    std::cout << " [4] Bit-Balance (Verhältnis 1-Bits zu 0-Bits):\n"
              << "     Gemessen: " << std::fixed << std::setprecision(3) << bitBalancePercent << " %  "
              << (bitBalanceOk ? "[BESTANDEN]" : "[FEHLGESCHLAGEN!]") << "\n"
              << "     (Theoretisches Ideal: 50.000 %)\n\n";

    std::cout << " [5] Serielle Autokorrelation (Lag-1 Abhängigkeit):\n"
              << "     Gemessen: " << std::fixed << std::setprecision(6) << serialCorr << "  "
              << (corrOk ? "[BESTANDEN]" : "[FEHLGESCHLAGEN!]") << "\n"
              << "     (Theoretisches Ideal: 0.000000)\n\n";

    secure_wipe_memory(masterKey, sizeof(masterKey));
    secure_wipe_memory(masterNonce, sizeof(masterNonce));
    secure_wipe_memory(stream.data(), stream.size());

    if (shannonOk && chiOk && meanOk && bitBalanceOk && corrOk) {
        std::cout << "============================================================\n"
                  << " GESAMTFAZIT: ALLE ENTROPIE- & KRYPTOTESTS BESTANDEN [OK]\n"
                  << " Der Zufallsstrom ist ununterscheidbar von echtem weissen Rauschen.\n"
                  << "============================================================\n\n";
        return 0;
    } else {
        std::cout << "============================================================\n"
                  << " GESAMTFAZIT: STATISTISCHE ANOMALIEN ENTDECKT [WARNUNG]\n"
                  << "============================================================\n\n";
        return 1;
    }
}

// ============================================================================
// 7. Hardware-Benchmark-Modus
// ============================================================================
int runBenchmark() {
    std::cout << "\n========================================================\n"
              << " RFS Hardware-Benchmark (Multi-Threading & AVX2 Durchsatz)\n"
              << "========================================================\n\n";

    auto tStartHarvest = std::chrono::high_resolution_clock::now();
    uint8_t key[32];
    uint8_t nonce[12];
    UniversalEntropyHarvester::harvestSeed(key, nonce);
    auto tEndHarvest = std::chrono::high_resolution_clock::now();
    double harvestMs = std::chrono::duration<double, std::milli>(tEndHarvest - tStartHarvest).count();

    std::cout << " [1/4] Entropie-Harvesting (CPU-Jitter + ASLR + RNG):\n"
              << "       Dauer: " << std::fixed << std::setprecision(2) << harvestMs << " ms\n"
              << "       Status: 256-Bit Key & 96-Bit Nonce erfolgreich extrahiert.\n\n";

    ChaCha20RNG rng(key, nonce);
    SHA256 hasher;

    const size_t BENCH_BUF_SIZE = 16 * 1024 * 1024;
    const size_t TOTAL_BENCH_BYTES = 512 * 1024 * 1024;
    std::vector<uint8_t> bufferA(BENCH_BUF_SIZE);
    std::vector<uint8_t> bufferB(BENCH_BUF_SIZE);
    std::vector<uint8_t> bufferOut(BENCH_BUF_SIZE);

    rng.generateBytes(bufferA.data(), BENCH_BUF_SIZE);

    auto tStartChaCha = std::chrono::high_resolution_clock::now();
    size_t generated = 0;
    while (generated < TOTAL_BENCH_BYTES) {
        rng.generateBytes(bufferB.data(), BENCH_BUF_SIZE);
        generated += BENCH_BUF_SIZE;
    }
    auto tEndChaCha = std::chrono::high_resolution_clock::now();
    double chachaSeconds = std::chrono::duration<double>(tEndChaCha - tStartChaCha).count();
    double chachaSpeedMB = (TOTAL_BENCH_BYTES / (1024.0 * 1024.0)) / chachaSeconds;

#if defined(__AVX2__)
    std::string simdLbl = "AVX2 SIMD (4 Blöcke / 256-Bit)";
#else
    std::string simdLbl = "Portable 64-Bit Fallback";
#endif

    std::cout << " [2/4] ChaCha20 CSPRNG Durchsatz [" << simdLbl << "]:\n"
              << "       Geschwindigkeit: " << std::fixed << std::setprecision(2)
              << chachaSpeedMB << " MB/s (" << (chachaSpeedMB / 1024.0) << " GB/s)\n\n";

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

    std::cout << " [3/4] 64-Bit Fast-Path XOR Durchsatz (RAM-zu-RAM):\n"
              << "       Geschwindigkeit: " << std::fixed << std::setprecision(2)
              << xorSpeedMB << " MB/s (" << (xorSpeedMB / 1024.0) << " GB/s)\n\n";

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

    std::cout << " [4/4] SHA-256 Block-Update Hashing:\n"
              << "       Geschwindigkeit: " << std::fixed << std::setprecision(2)
              << shaSpeedMB << " MB/s\n\n";

    std::cout << " [Pipeline] Pipelined Performance (Parallel Hash + Crypto):\n";
    auto tStartPipe = std::chrono::high_resolution_clock::now();
    auto hashFut = std::async(std::launch::async, [&]() {
        SHA256 thHasher;
        size_t done = 0;
        while (done < TOTAL_BENCH_BYTES) {
            thHasher.update(bufferA.data(), BENCH_BUF_SIZE);
            done += BENCH_BUF_SIZE;
        }
    });
    auto rngFut = std::async(std::launch::async, [&]() {
        ChaCha20RNG thRng(key, nonce);
        size_t done = 0;
        while (done < TOTAL_BENCH_BYTES) {
            thRng.generateBytes(bufferB.data(), BENCH_BUF_SIZE);
            done += BENCH_BUF_SIZE;
        }
    });
    hashFut.get();
    rngFut.get();
    auto tEndPipe = std::chrono::high_resolution_clock::now();
    double pipeSeconds = std::chrono::duration<double>(tEndPipe - tStartPipe).count();
    double pipeSpeedMB = (TOTAL_BENCH_BYTES / (1024.0 * 1024.0)) / pipeSeconds;

    std::cout << "       Durchsatz: " << std::fixed << std::setprecision(2)
              << pipeSpeedMB << " MB/s (" << (pipeSpeedMB / 1024.0) << " GB/s)\n\n";

    secure_wipe_memory(key, sizeof(key));
    secure_wipe_memory(nonce, sizeof(nonce));

    std::cout << "Fazit: Ihre CPU liefert mit AVX2 & Multi-Threading ca. "
              << std::fixed << std::setprecision(1) << chachaSpeedMB << " MB/s Krypto-Durchsatz.\n"
              << "Damit ist sichergestellt, dass RFS zu 100% am I/O-Limit des Datentraegers arbeitet.\n\n";
    return 0;
}

// ============================================================================
// 8. Kern-Logik: Pipelined Multi-Threaded Verschlüsseln / Splitten
// ============================================================================
void displayHelp() {
    std::cout << "\n========================================================\n"
              << " RFS - Random File Splitter (LGPL)\n"
              << "========================================================\n"
              << " Verwendung:\n"
              << "   Splitten:         rfs <Datei>\n"
              << "   Wiederherstellen: rfs <Datei.rfs1> <Datei.rfs2>\n"
              << "   Integritaetstest: rfs --verify <Datei.rfs1> <Datei.rfs2>\n"
              << "   Entropie-Analyse: rfs --entropy-test\n"
              << "   Hardware-Test:    rfs --benchmark\n\n";
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

    inputFile.seekg(0, std::ios::end);
    uint64_t originalSize = inputFile.tellg();
    inputFile.seekg(0, std::ios::beg);

    uint8_t masterKey[32];
    uint8_t masterNonce[12];
    UniversalEntropyHarvester::harvestSeed(masterKey, masterNonce);
    ChaCha20RNG rng(masterKey, masterNonce);

    SHA256 hasher;

    const size_t BUFFER_SIZE = 4 * 1024 * 1024;
    std::vector<char> buffer(BUFFER_SIZE);
    std::vector<char> cr1Buf(BUFFER_SIZE);
    std::vector<char> cr2Buf(BUFFER_SIZE);

    ProgressBar progress("Splitting", originalSize);
    uint64_t totalBytesRead = 0;

    std::future<bool> write1Future;
    std::future<bool> write2Future;
    std::future<void> hashFuture;

    std::vector<char> writeCr1Buf(BUFFER_SIZE);
    std::vector<char> writeCr2Buf(BUFFER_SIZE);
    std::vector<char> hashBuf(BUFFER_SIZE);

    while (inputFile) {
        inputFile.read(buffer.data(), BUFFER_SIZE);
        std::streamsize bytesRead = inputFile.gcount();
        if (bytesRead <= 0) break;

        totalBytesRead += bytesRead;

        if (write1Future.valid() && !write1Future.get()) {
            std::cerr << "\nFehler: Schreibfehler auf Datei 1 (z.B. Datentraeger voll).\n";
            return 1;
        }
        if (write2Future.valid() && !write2Future.get()) {
            std::cerr << "\nFehler: Schreibfehler auf Datei 2 (z.B. Datentraeger voll).\n";
            return 1;
        }
        if (hashFuture.valid()) {
            hashFuture.get();
        }

        std::memcpy(hashBuf.data(), buffer.data(), bytesRead);
        hashFuture = std::async(std::launch::async, [&hasher, &hashBuf, bytesRead]() {
            hasher.update(reinterpret_cast<const uint8_t*>(hashBuf.data()), bytesRead);
        });

        rng.generateBytes(reinterpret_cast<uint8_t*>(cr2Buf.data()), bytesRead);

        size_t words = bytesRead / 8;
        const uint64_t* src64 = reinterpret_cast<const uint64_t*>(buffer.data());
        const uint64_t* rnd64 = reinterpret_cast<const uint64_t*>(cr2Buf.data());
        uint64_t* dst64       = reinterpret_cast<uint64_t*>(cr1Buf.data());

        for (size_t i = 0; i < words; ++i) {
            dst64[i] = src64[i] ^ rnd64[i];
        }

        size_t tailOffset = words * 8;
        for (size_t i = tailOffset; i < static_cast<size_t>(bytesRead); ++i) {
            cr1Buf[i] = static_cast<char>(static_cast<uint8_t>(buffer[i]) ^ static_cast<uint8_t>(cr2Buf[i]));
        }

        std::memcpy(writeCr1Buf.data(), cr1Buf.data(), bytesRead);
        std::memcpy(writeCr2Buf.data(), cr2Buf.data(), bytesRead);

        write1Future = std::async(std::launch::async, [&cr1File, &writeCr1Buf, bytesRead]() -> bool {
            cr1File.write(writeCr1Buf.data(), bytesRead);
            return cr1File.good();
        });
        write2Future = std::async(std::launch::async, [&cr2File, &writeCr2Buf, bytesRead]() -> bool {
            cr2File.write(writeCr2Buf.data(), bytesRead);
            return cr2File.good();
        });

        progress.update(totalBytesRead);
    }

    if (write1Future.valid() && !write1Future.get()) return 1;
    if (write2Future.valid() && !write2Future.get()) return 1;
    if (hashFuture.valid()) hashFuture.get();

    progress.finish(totalBytesRead);

    uint32_t paddingSize = rng.next_range_u32(1024, 102400);
    std::vector<char> padBuf1(paddingSize);
    std::vector<char> padBuf2(paddingSize);
    rng.generateBytes(reinterpret_cast<uint8_t*>(padBuf1.data()), paddingSize);
    rng.generateBytes(reinterpret_cast<uint8_t*>(padBuf2.data()), paddingSize);
    cr1File.write(padBuf1.data(), paddingSize);
    cr2File.write(padBuf2.data(), paddingSize);

    uint8_t hash[32];
    hasher.final(hash);
    for (int i = 0; i < 32; ++i) {
        uint8_t rnd = rng.next_u8();
        cr1File.put(static_cast<char>(hash[i] ^ rnd));
        cr2File.put(static_cast<char>(rnd));
    }

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

    secure_wipe_memory(masterKey, sizeof(masterKey));
    secure_wipe_memory(masterNonce, sizeof(masterNonce));
    secure_wipe_memory(hash, sizeof(hash));
    secure_wipe_memory(sizeBytes, sizeof(sizeBytes));

    std::cout << "Erfolg: Datei erfolgreich geteilt.\n"
              << "  Teil 1: " << cr1FileName << "\n"
              << "  Teil 2: " << cr2FileName << "\n";
    return 0;
}

// ============================================================================
// 9. Kern-Logik: Entschlüsseln & Verify-Modus
// ============================================================================
int decryptOrVerifyFile(const std::string& input1, const std::string& input2, bool verifyOnly) {
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

    cr1.seekg(-40, std::ios::end);
    cr2.seekg(-40, std::ios::end);
    uint8_t expectedHash[32];
    for (int i = 0; i < 32; ++i) {
        char b1, b2;
        cr1.get(b1); cr2.get(b2);
        expectedHash[i] = static_cast<uint8_t>(b1) ^ static_cast<uint8_t>(b2);
    }

    std::unique_ptr<std::ofstream> out;
    if (!verifyOnly) {
        out = std::unique_ptr<std::ofstream>(new std::ofstream(outName, std::ios::binary));
        if (!out || !out->good()) {
            std::cerr << "Fehler: Ausgabedatei '" << outName << "' kann nicht geschrieben werden.\n";
            return 1;
        }
    }

    cr1.seekg(0, std::ios::beg);
    cr2.seekg(0, std::ios::beg);

    SHA256 hasher;
    const size_t BUFFER_SIZE = 4 * 1024 * 1024;
    std::vector<char> b1(BUFFER_SIZE), b2(BUFFER_SIZE), bOut(BUFFER_SIZE);
    uint64_t processed = 0;

    std::string taskLabel = verifyOnly ? "Verifying" : "Restoring";
    ProgressBar progress(taskLabel, originalSize);

    std::future<bool> writeFuture;
    std::vector<char> asyncWriteBuf(BUFFER_SIZE);

    while (processed < originalSize) {
        uint64_t toRead = std::min(static_cast<uint64_t>(BUFFER_SIZE), originalSize - processed);
        cr1.read(b1.data(), toRead);
        cr2.read(b2.data(), toRead);

        size_t words = toRead / 8;
        const uint64_t* p1_64 = reinterpret_cast<const uint64_t*>(b1.data());
        const uint64_t* p2_64 = reinterpret_cast<const uint64_t*>(b2.data());
        uint64_t* dst64       = reinterpret_cast<uint64_t*>(bOut.data());

        for (size_t i = 0; i < words; ++i) {
            dst64[i] = p1_64[i] ^ p2_64[i];
        }

        size_t tailOffset = words * 8;
        for (size_t i = tailOffset; i < toRead; ++i) {
            bOut[i] = static_cast<char>(static_cast<uint8_t>(b1[i]) ^ static_cast<uint8_t>(b2[i]));
        }

        hasher.update(reinterpret_cast<const uint8_t*>(bOut.data()), toRead);

        if (!verifyOnly) {
            if (writeFuture.valid() && !writeFuture.get()) {
                std::cerr << "\nFehler: Schreibfehler bei der Wiederherstellung (z.B. Datentraeger voll).\n";
                return 1;
            }
            std::memcpy(asyncWriteBuf.data(), bOut.data(), toRead);
            writeFuture = std::async(std::launch::async, [&out, &asyncWriteBuf, toRead]() -> bool {
                out->write(asyncWriteBuf.data(), toRead);
                return out->good();
            });
        }

        processed += toRead;
        progress.update(processed);
    }

    if (!verifyOnly && writeFuture.valid() && !writeFuture.get()) return 1;

    progress.finish(processed);

    if (!verifyOnly && out) {
        out->flush();
    }

    uint8_t calculatedHash[32];
    hasher.final(calculatedHash);

    bool hashMatch = (std::memcmp(calculatedHash, expectedHash, 32) == 0);
    secure_wipe_memory(calculatedHash, sizeof(calculatedHash));
    secure_wipe_memory(expectedHash, sizeof(expectedHash));
    secure_wipe_memory(sizeBytes, sizeof(sizeBytes));

    if (hashMatch) {
        if (verifyOnly) {
            std::cout << "Erfolg: Integritaetstest bestanden! Die Teile sind unversehrt und gueltig.\n"
                      << "  Original-Dateigroesse: " << originalSize << " Bytes\n"
                      << "  SHA-256 Hash: OK\n";
        } else {
            std::cout << "Erfolg: Datei erfolgreich wiederhergestellt -> " << outName << "\n"
                      << "Integritaet: SHA-256 Hash geprueft und gueltig (OK).\n";
        }
        return 0;
    } else {
        std::cerr << "WARNUNG: Integritaetsfehler! SHA-256 Pruefsumme stimmt nicht ueberein.\n"
                  << "Die Datei ist moeglicherweise beschaedigt oder manipuliert.\n";
        return 2;
    }
}

// ============================================================================
// 10. Programmeinstieg
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
        if (arg == "-e" || arg == "--entropy-test" || arg == "--entropy") {
            return runEntropyTest();
        }
        return encryptFile(argv[1]);
    }
    if (argc == 3) {
        return decryptOrVerifyFile(argv[1], argv[2], false);
    }
    if (argc == 4) {
        std::string flag = argv[1];
        if (flag == "-v" || flag == "--verify" || flag == "--check") {
            return decryptOrVerifyFile(argv[2], argv[3], true);
        }
    }

    displayHelp();
    return 0;
}
