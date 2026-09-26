#include "rfs/chacha20.hpp"
#include <algorithm>
#include <cstring>

namespace rfs {

ChaCha20RNG::ChaCha20RNG(const uint8_t key[32], const uint8_t nonce[12], uint32_t initialCounter) {
    reset(key, nonce, initialCounter);
}

ChaCha20RNG::~ChaCha20RNG() {
    wipe();
}

void ChaCha20RNG::reset(const uint8_t key[32], const uint8_t nonce[12], uint32_t initialCounter) {
    m_bufferPos = 64;

    // "expand 32-byte k"
    m_state[0] = 0x61707865;
    m_state[1] = 0x3320646e;
    m_state[2] = 0x79622d32;
    m_state[3] = 0x6b206574;

    for (int i = 0; i < 8; ++i) {
        m_state[4 + i] = read_u32_le(key + i * 4);
    }

    m_state[12] = initialCounter;
    m_state[13] = read_u32_le(nonce + 0);
    m_state[14] = read_u32_le(nonce + 4);
    m_state[15] = read_u32_le(nonce + 8);
}

void ChaCha20RNG::wipe() {
    secure_wipe_memory(m_state, sizeof(m_state));
    secure_wipe_memory(m_keystreamBuffer, sizeof(m_keystreamBuffer));
    m_bufferPos = 64;
}

void ChaCha20RNG::generateBytes(uint8_t* destination, size_t length) {
    size_t offset = 0;

    if (m_bufferPos < 64) {
        size_t available = 64 - m_bufferPos;
        size_t toCopy = std::min(available, length);
        std::memcpy(destination, m_keystreamBuffer + m_bufferPos, toCopy);
        m_bufferPos += toCopy;
        offset += toCopy;
    }

#if defined(__AVX2__)
    while (offset + 512 <= length) {
        generate8BlocksAVX2(destination + offset);
        offset += 512;
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

uint64_t ChaCha20RNG::next_u64() {
    uint64_t val;
    generateBytes(reinterpret_cast<uint8_t*>(&val), sizeof(val));
    return val;
}

uint8_t ChaCha20RNG::next_u8() {
    uint8_t val;
    generateBytes(&val, 1);
    return val;
}

uint32_t ChaCha20RNG::next_range_u32(uint32_t min, uint32_t max) {
    if (min >= max) return min;
    uint32_t range = max - min + 1;
    uint32_t x;
    generateBytes(reinterpret_cast<uint8_t*>(&x), sizeof(x));
    return min + (x % range);
}

void ChaCha20RNG::generateBlock(uint8_t output[64]) {
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
        write_u32_le(output + i * 4, x[i] + m_state[i]);
    }

    m_state[12]++;
}

#if defined(__AVX2__)
void ChaCha20RNG::generate8BlocksAVX2(uint8_t output[512]) {
    __m256i s[16];
    for (int i = 0; i < 16; ++i) {
        if (i == 12) {
            s[12] = _mm256_set_epi32(m_state[12] + 7, m_state[12] + 6, m_state[12] + 5, m_state[12] + 4,
                                     m_state[12] + 3, m_state[12] + 2, m_state[12] + 1, m_state[12] + 0);
        } else {
            s[i] = _mm256_set1_epi32(m_state[i]);
        }
    }

    __m256i x[16];
    for (int i = 0; i < 16; ++i) {
        x[i] = s[i];
    }

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

    for (int b = 0; b < 8; ++b) {
        uint8_t* blockOut = output + b * 64;
        for (int i = 0; i < 16; ++i) {
            write_u32_le(blockOut + i * 4, tmp[i][b]);
        }
    }

    m_state[12] += 8;
}
#endif

} // namespace rfs
