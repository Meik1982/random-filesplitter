#ifndef RFS_ENTROPY_HPP
#define RFS_ENTROPY_HPP

#include <cstdint>
#include <cstddef>
#include "types.hpp"

namespace rfs {

class UniversalEntropyHarvester {
public:
    static void harvestSeed(uint8_t key[32], uint8_t nonce[12]);
};

int runEntropyTest();

} // namespace rfs

#endif // RFS_ENTROPY_HPP
