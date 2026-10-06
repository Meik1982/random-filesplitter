#ifndef RFS_SHA256_HPP
#define RFS_SHA256_HPP

#include <cstdint>
#include <cstddef>
#include "types.hpp"

namespace rfs {

class SHA256 {
public:
    SHA256();
    ~SHA256();

    SHA256(const SHA256&) = delete;
    SHA256& operator=(const SHA256&) = delete;

    void update(const uint8_t* data, size_t len);
    void final(uint8_t hash[32]);
    void reset();
    void wipe();

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

    void transform(const uint8_t block[64]);
};

} // namespace rfs

#endif // RFS_SHA256_HPP
