#ifndef RFS_CHACHA20_HPP
#define RFS_CHACHA20_HPP

#include <cstdint>
#include <cstddef>
#include "types.hpp"

#if defined(__AVX2__)
#include <immintrin.h>
#endif

namespace rfs {

class ChaCha20RNG {
public:
    ChaCha20RNG(const uint8_t key[32], const uint8_t nonce[12], uint32_t initialCounter = 1);
    ~ChaCha20RNG();

    ChaCha20RNG(const ChaCha20RNG&) = delete;
    ChaCha20RNG& operator=(const ChaCha20RNG&) = delete;

    void generateBytes(uint8_t* destination, size_t length);

    uint64_t next_u64();
    uint8_t next_u8();
    uint32_t next_range_u32(uint32_t min, uint32_t max);

    void reset(const uint8_t key[32], const uint8_t nonce[12], uint32_t initialCounter = 1);
    void wipe();

private:
    uint32_t m_state[16];
    uint8_t  m_keystreamBuffer[64];
    size_t   m_bufferPos;

    static inline uint32_t rotl(uint32_t v, int c) {
        return (v << c) | (v >> (32 - c));
    }

    static inline void quarterRound(uint32_t& a, uint32_t& b, uint32_t& c, uint32_t& d) {
        a += b; d ^= a; d = rotl(d, 16);
        c += d; b ^= c; b = rotl(b, 12);
        a += b; d ^= a; d = rotl(d, 8);
        c += d; b ^= c; b = rotl(b, 7);
    }

    void generateBlock(uint8_t output[64]);

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

    void generate8BlocksAVX2(uint8_t output[512]);
#endif
};

} // namespace rfs

#endif // RFS_CHACHA20_HPP
