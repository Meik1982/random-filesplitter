#include "rfs/entropy.hpp"
#include "rfs/sha256.hpp"
#include "rfs/chacha20.hpp"
#include "rfs/types.hpp"
#include <iostream>
#include <iomanip>
#include <fstream>
#include <vector>
#include <chrono>
#include <random>
#include <cmath>
#include <map>
#include <numeric>
#include <cstring>

#if defined(__linux__)
#include <sys/random.h>
#include <fcntl.h>
#include <unistd.h>
#elif defined(_WIN32)
#include <bcrypt.h>
#elif defined(__unix__) || defined(__APPLE__)
#include <fcntl.h>
#include <unistd.h>
#endif

namespace rfs {

namespace {

// 32K Elemente * 64 Bytes (1 Cache-Line) = 2 MB Puffer
// Sprengt L1 und L2 Caches gängiger Kerne zur Erzeugung von Bus-/Cache-Latenzen
constexpr size_t POOL_NODES = 32768;

struct CacheLineNode {
    uint32_t next;
    uint8_t pad[60];
};

void initPermutationPool(std::vector<CacheLineNode>& pool, uint32_t seedVal) {
    std::vector<uint32_t> perm(POOL_NODES);
    std::iota(perm.begin(), perm.end(), 0);

    // Sattolo-Zyklus: Garantiert genau 1 vollständigen, ununterbrochenen Kreis
    // verhindert deterministische Stream-Prefetching-Treffer der CPU
    std::mt19937 rng(seedVal);
    for (size_t i = POOL_NODES - 1; i > 0; --i) {
        std::uniform_int_distribution<size_t> dist(0, i - 1);
        std::swap(perm[i], perm[dist(rng)]);
    }

    for (size_t i = 0; i < POOL_NODES; ++i) {
        pool[i].next = perm[i];
    }
}

} // namespace

void UniversalEntropyHarvester::harvestSeed(uint8_t key[32], uint8_t nonce[12]) {
    SHA256 hasher;

    // 1. Betriebssystem-Kernel-CSPRNG (Linux getrandom, Windows BCrypt, /dev/urandom)
    uint8_t osEntropy[64];
    bool osEntropySuccess = false;

#if defined(__linux__)
    ssize_t ret = getrandom(osEntropy, sizeof(osEntropy), 0);
    if (ret == static_cast<ssize_t>(sizeof(osEntropy))) {
        osEntropySuccess = true;
    } else {
        int fd = open("/dev/urandom", O_RDONLY | O_CLOEXEC);
        if (fd >= 0) {
            ssize_t r = read(fd, osEntropy, sizeof(osEntropy));
            if (r == static_cast<ssize_t>(sizeof(osEntropy))) {
                osEntropySuccess = true;
            }
            close(fd);
        }
    }
#elif defined(_WIN32)
    if (BCryptGenRandom(NULL, osEntropy, sizeof(osEntropy), BCRYPT_USE_SYSTEM_PREFERRED_RNG) == 0) {
        osEntropySuccess = true;
    }
#elif defined(__unix__) || defined(__APPLE__)
    int fd = open("/dev/urandom", O_RDONLY);
    if (fd >= 0) {
        ssize_t r = read(fd, osEntropy, sizeof(osEntropy));
        if (r == static_cast<ssize_t>(sizeof(osEntropy))) {
            osEntropySuccess = true;
        }
        close(fd);
    }
#endif

    if (osEntropySuccess) {
        hasher.update(osEntropy, sizeof(osEntropy));
        secure_wipe_memory(osEntropy, sizeof(osEntropy));
    }

    // 2. Hardware-Zufall (TRNG / CPU RDRAND falls vorhanden)
    try {
        std::random_device rd;
        for (int i = 0; i < 32; ++i) {
            unsigned int r = rd();
            hasher.update(reinterpret_cast<const uint8_t*>(&r), sizeof(r));
        }
    } catch (...) {
    }

    // 3. High-Resolution & Monotonic Clocks
    auto nowWall = std::chrono::system_clock::now().time_since_epoch().count();
    auto nowMono = std::chrono::steady_clock::now().time_since_epoch().count();
    auto nowHigh = std::chrono::high_resolution_clock::now().time_since_epoch().count();
    hasher.update(reinterpret_cast<const uint8_t*>(&nowWall), sizeof(nowWall));
    hasher.update(reinterpret_cast<const uint8_t*>(&nowMono), sizeof(nowMono));
    hasher.update(reinterpret_cast<const uint8_t*>(&nowHigh), sizeof(nowHigh));

    // 3. ASLR Adress-Layout
    int stackVar = 42;
    int* heapVar = new int(1337);
    void (*funcPtr)(uint8_t*, uint8_t*) = &UniversalEntropyHarvester::harvestSeed;
    uintptr_t sAddr = reinterpret_cast<uintptr_t>(&stackVar);
    uintptr_t hAddr = reinterpret_cast<uintptr_t>(heapVar);
    uintptr_t fAddr = reinterpret_cast<uintptr_t>(funcPtr);
    delete heapVar;

    hasher.update(reinterpret_cast<const uint8_t*>(&sAddr), sizeof(sAddr));
    hasher.update(reinterpret_cast<const uint8_t*>(&hAddr), sizeof(hAddr));
    hasher.update(reinterpret_cast<const uint8_t*>(&fAddr), sizeof(fAddr));

    // 4. Nicht-vorhersagbarer Cache-/Memory-Jitter
    std::vector<CacheLineNode> pool(POOL_NODES);
    initPermutationPool(pool, static_cast<uint32_t>(nowHigh & 0xFFFFFFFF));

    uint32_t curr = static_cast<uint32_t>(sAddr % POOL_NODES);
    for (int i = 0; i < 2048; ++i) {
        auto t1 = std::chrono::high_resolution_clock::now();
        for (int j = 0; j < 64; ++j) {
            curr = pool[curr].next;
#if defined(__GNUC__) || defined(__clang__)
            __asm__ __volatile__("" : "+r"(curr));
#endif
        }
        auto t2 = std::chrono::high_resolution_clock::now();
        int64_t diff = (t2 - t1).count();
        hasher.update(reinterpret_cast<const uint8_t*>(&diff), sizeof(diff));
        hasher.update(reinterpret_cast<const uint8_t*>(&curr), sizeof(curr));
    }

    hasher.final(key);

    // KDF für Nonce: Einweg-Ableitung via SHA-256
    hasher.reset();
    hasher.update(key, 32);
    const char nonceSalt[] = "rfs2-universal-nonce-salt-v2";
    hasher.update(reinterpret_cast<const uint8_t*>(nonceSalt), sizeof(nonceSalt) - 1);
    uint8_t nonceHash[32];
    hasher.final(nonceHash);
    std::memcpy(nonce, nonceHash, 12);
    secure_wipe_memory(nonceHash, sizeof(nonceHash));
}

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

    std::vector<CacheLineNode> pool(POOL_NODES);
    initPermutationPool(pool, 1337);

    uint32_t curr = 0;
    for (size_t i = 0; i < JITTER_SAMPLES; ++i) {
        auto t1 = std::chrono::high_resolution_clock::now();
        for (int j = 0; j < 64; ++j) {
            curr = pool[curr].next;
#if defined(__GNUC__) || defined(__clang__)
            __asm__ __volatile__("" : "+r"(curr));
#endif
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
    bool phase1Ok = jitterVarianceOk && jitterBucketsOk && jitterBitFlipsOk && jitterEntropyOk;

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

    if (phase1Ok) {
        std::cout << "Status Phase 1: [OK] Die CPU liefert echte physikalische Timing-Entropie.\n\n";
    } else {
        std::cout << "WARNUNG Phase 1: [FEHLER] Keine oder unzureichende CPU-Jitter-Entropie!\n\n";
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
    bool phase2Ok = shannonOk && chiOk && meanOk && bitBalanceOk && corrOk;

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

    if (phase1Ok && phase2Ok) {
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

int analyzeFileEntropy(const std::string& path) {
    std::ifstream file(path, std::ios::binary);
    if (!file.is_open()) {
        std::cerr << "Fehler: Datei '" << path << "' konnte nicht geoeffnet werden.\n";
        return 1;
    }

    file.seekg(0, std::ios::end);
    uint64_t fileSize = static_cast<uint64_t>(file.tellg());
    file.seekg(0, std::ios::beg);

    if (fileSize == 0) {
        std::cerr << "Fehler: Datei '" << path << "' ist leer (0 Bytes). Entropie kann nicht bestimmt werden.\n";
        return 1;
    }

    std::cout << "\n============================================================\n"
              << " RFS Kryptoanalytische Datei-Entropieanalyse\n"
              << "============================================================\n"
              << " Datei:   " << path << "\n"
              << " Groesse: " << fileSize << " Bytes ("
              << std::fixed << std::setprecision(2) << (static_cast<double>(fileSize) / (1024.0 * 1024.0)) << " MB)\n"
              << "------------------------------------------------------------\n";

    constexpr size_t CHUNK_SIZE = 1024 * 1024;
    std::vector<uint8_t> buffer(CHUNK_SIZE);

    uint64_t counts[256] = {0};
    uint64_t totalBytes = 0;
    uint64_t totalOnes = 0;
    double sumBytes = 0.0;

    double corrNumerator = 0.0;
    double corrDenom = 0.0;
    int prevByte = -1;

    uint64_t mcInCircle = 0;
    uint64_t mcTotalPairs = 0;
    int mcPendingByte = -1;

    while (file.good() && totalBytes < fileSize) {
        file.read(reinterpret_cast<char*>(buffer.data()), CHUNK_SIZE);
        size_t bytesRead = static_cast<size_t>(file.gcount());
        if (bytesRead == 0) break;

        for (size_t i = 0; i < bytesRead; ++i) {
            uint8_t b = buffer[i];
            counts[b]++;
            sumBytes += b;
#if defined(__GNUC__) || defined(__clang__)
            totalOnes += __builtin_popcount(b);
#else
            for (int bit = 0; bit < 8; ++bit) totalOnes += ((b >> bit) & 1);
#endif
            if (prevByte >= 0) {
                double x = static_cast<double>(prevByte) - 127.5;
                double y = static_cast<double>(b) - 127.5;
                corrNumerator += (x * y);
                corrDenom += (x * x);
            }
            prevByte = b;

            if (mcPendingByte < 0) {
                mcPendingByte = b;
            } else {
                double x = (static_cast<double>(mcPendingByte) + 0.5) / 256.0;
                double y = (static_cast<double>(b) + 0.5) / 256.0;
                if ((x * x + y * y) <= 1.0) {
                    mcInCircle++;
                }
                mcTotalPairs++;
                mcPendingByte = -1;
            }
        }
        totalBytes += bytesRead;
    }

    if (totalBytes == 0) {
        std::cerr << "Fehler: Keine Daten gelesen.\n";
        return 1;
    }

    // 1. Shannon-Entropie
    double shannonEntropy = 0.0;
    for (int i = 0; i < 256; ++i) {
        if (counts[i] > 0) {
            double p = static_cast<double>(counts[i]) / totalBytes;
            shannonEntropy -= p * (std::log(p) / std::log(2.0));
        }
    }
    double entropyRatio = (shannonEntropy / 8.0) * 100.0;

    // 2. Chi-Quadrat Test (df = 255)
    double expected = static_cast<double>(totalBytes) / 256.0;
    double chiSquare = 0.0;
    for (int i = 0; i < 256; ++i) {
        double diff = static_cast<double>(counts[i]) - expected;
        chiSquare += (diff * diff) / expected;
    }

    // 3. Arithmetischer Mittelwert
    double mean = sumBytes / totalBytes;

    // 4. Bit-Balance
    double bitBalance = (static_cast<double>(totalOnes) / (totalBytes * 8.0)) * 100.0;

    // 5. Serielle Autokorrelation
    double serialCorr = (corrDenom > 0.0) ? (corrNumerator / corrDenom) : 0.0;

    // 6. Monte Carlo Pi
    double piEst = 0.0;
    double piErrorPercent = 0.0;
    constexpr double PI_ACTUAL = 3.14159265358979323846;
    if (mcTotalPairs > 0) {
        piEst = 4.0 * (static_cast<double>(mcInCircle) / static_cast<double>(mcTotalPairs));
        piErrorPercent = std::abs(piEst - PI_ACTUAL) / PI_ACTUAL * 100.0;
    }

    // Ausgabe
    std::cout << " [1] Shannon-Entropie:\n"
              << "     Gemessen:        " << std::fixed << std::setprecision(6) << shannonEntropy << " Bits / Byte\n"
              << "     Entropiedichte:  " << std::fixed << std::setprecision(2) << entropyRatio << " % des theoretischen Maximums (8.000000)\n\n";

    std::cout << " [2] Chi-Quadrat Anpassungstest (df = 255):\n"
              << "     Wert:            " << std::fixed << std::setprecision(2) << chiSquare << "\n";
    if (totalBytes < 2560) {
        std::cout << "     Hinweis:         Dateigroesse klein (< 2.5 KB), Chi-Quadrat nur eingeschraenkt aussagekraeftig.\n\n";
    } else {
        std::cout << "     Idealbereich:    180.00 - 330.00 (fuer 95 % Gleichverteilung)\n\n";
    }

    std::cout << " [3] Arithmetischer Mittelwert:\n"
              << "     Gemessen:        " << std::fixed << std::setprecision(3) << mean << "\n"
              << "     Ideal:           127.500 (Abweichung: " << std::abs(mean - 127.5) << ")\n\n";

    std::cout << " [4] Bit-Balance (1-Bits zu 0-Bits):\n"
              << "     Gemessen:        " << std::fixed << std::setprecision(3) << bitBalance << " %\n"
              << "     Ideal:           50.000 % (Abweichung: " << std::abs(bitBalance - 50.0) << " %)\n\n";

    std::cout << " [5] Serielle Autokorrelation (Lag-1):\n"
              << "     Gemessen:        " << std::fixed << std::setprecision(6) << serialCorr << "\n"
              << "     Ideal:           0.000000\n\n";

    std::cout << " [6] Monte-Carlo-Schaetzung von Pi:\n"
              << "     Geschaetzt:      " << std::fixed << std::setprecision(6) << piEst << "\n"
              << "     Abweichung:      " << std::fixed << std::setprecision(3) << piErrorPercent << " % von Pi\n\n";

    std::cout << "============================================================\n"
              << " KRYPTOANALYTISCHE BEWERTUNG:\n"
              << "============================================================\n";

    if (shannonEntropy >= 7.9990 && chiSquare >= 180.0 && chiSquare <= 330.0 && std::abs(serialCorr) < 0.002) {
        std::cout << " Einstufung: SEHR HOHE ENTROPIE (Kryptografische Guete)\n"
                  << " Analyse:    Die Daten sind statistisch ununterscheidbar von echtem weissen\n"
                  << "             Rauschen. Verhalten deckt sich mit starker Ciphertext-Verschluesselung\n"
                  << "             (z. B. ChaCha20, AES) oder kryptografischen CSPRNG-Stroemen.\n";
    } else if (shannonEntropy >= 7.9500) {
        std::cout << " Einstufung: HOHE ENTROPIE (Ciphertext oder starke Kompression)\n"
                  << " Analyse:    Sehr hohe Gleichverteilung. Typisch fuer stark komprimierte Archive\n"
                  << "             (z. B. gzip, zstd, xz) oder verschluesselte Bloecke mit geringen Randeffekten.\n";
    } else if (shannonEntropy >= 6.5000) {
        std::cout << " Einstufung: MITTLERE ENTROPIE (Binärcode / Teilstrukturiert)\n"
                  << " Analyse:    Typisch fuer ausfuehrbaren Maschinencode (ELF / PE Binaries),\n"
                  << "             unkomprimierte Bilder, Bytecode oder schwach verschluesselte Daten.\n";
    } else {
        std::cout << " Einstufung: NIEDRIGE ENTROPIE (Klartext / Strukturierte Daten)\n"
                  << " Analyse:    Hohe Redundanz und erkennbare Muster. Typisch fuer Textdateien,\n"
                  << "             Quellcode, JSON, XML, Datenbanken oder Null-Bytes.\n";
    }
    std::cout << "============================================================\n\n";

    return 0;
}

} // namespace rfs
