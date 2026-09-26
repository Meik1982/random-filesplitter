#ifndef RFS_ENTROPY_HPP
#define RFS_ENTROPY_HPP

#include <cstdint>
#include <cstddef>
#include <string>
#include "types.hpp"

namespace rfs {

class UniversalEntropyHarvester {
public:
    static void harvestSeed(uint8_t key[32], uint8_t nonce[12]);
};

// Systemdiagnose (CPU Jitter & interner Krypto-Stream)
int runEntropyTest();

// Kryptoanalytische Entropie-Analyse einer beliebigen Datei
int analyzeFileEntropy(const std::string& path);

} // namespace rfs

#endif // RFS_ENTROPY_HPP
