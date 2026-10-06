#include "rfs/sha256.hpp"
#include <algorithm>
#include <cstring>

namespace rfs {

#define SHA256_ROTR(x, n) (((x) >> (n)) | ((x) << (32 - (n))))

namespace {

const uint32_t K[64] = {
    0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
    0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
    0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
    0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
    0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
    0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
    0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
};

} // namespace

SHA256::SHA256() {
    reset();
}

SHA256::~SHA256() {
    wipe();
}

void SHA256::reset() {
    m_state[0] = 0x6a09e667;
    m_state[1] = 0xbb67ae85;
    m_state[2] = 0x3c6ef372;
    m_state[3] = 0xa54ff53a;
    m_state[4] = 0x510e527f;
    m_state[5] = 0x9b05688c;
    m_state[6] = 0x1f83d9ab;
    m_state[7] = 0x5be0cd19;
    m_buffer_len = 0;
    m_bit_len = 0;
}

void SHA256::wipe() {
    secure_wipe_memory(m_state, sizeof(m_state));
    secure_wipe_memory(m_buffer, sizeof(m_buffer));
    m_buffer_len = 0;
    m_bit_len = 0;
}

void SHA256::transform(const uint8_t block[64]) {
    uint32_t m[64];
    for (int i = 0; i < 16; ++i) {
        m[i] = (static_cast<uint32_t>(block[i * 4]) << 24)
             | (static_cast<uint32_t>(block[i * 4 + 1]) << 16)
             | (static_cast<uint32_t>(block[i * 4 + 2]) << 8)
             | (static_cast<uint32_t>(block[i * 4 + 3]));
    }
    for (int i = 16; i < 64; ++i) {
        m[i] = (SHA256_ROTR(m[i-2], 17) ^ SHA256_ROTR(m[i-2], 19) ^ (m[i-2] >> 10))
             + m[i-7]
             + (SHA256_ROTR(m[i-15], 7) ^ SHA256_ROTR(m[i-15], 18) ^ (m[i-15] >> 3))
             + m[i-16];
    }

    uint32_t a = m_state[0];
    uint32_t b = m_state[1];
    uint32_t c = m_state[2];
    uint32_t d = m_state[3];
    uint32_t e = m_state[4];
    uint32_t f = m_state[5];
    uint32_t g = m_state[6];
    uint32_t h = m_state[7];

    for (int i = 0; i < 64; ++i) {
        uint32_t s1 = SHA256_ROTR(e, 6) ^ SHA256_ROTR(e, 11) ^ SHA256_ROTR(e, 25);
        uint32_t t1 = h + s1 + ch(e, f, g) + K[i] + m[i];
        uint32_t s0 = SHA256_ROTR(a, 2) ^ SHA256_ROTR(a, 13) ^ SHA256_ROTR(a, 22);
        uint32_t t2 = s0 + maj(a, b, c);

        h = g;
        g = f;
        f = e;
        e = d + t1;
        d = c;
        c = b;
        b = a;
        a = t1 + t2;
    }

    m_state[0] += a;
    m_state[1] += b;
    m_state[2] += c;
    m_state[3] += d;
    m_state[4] += e;
    m_state[5] += f;
    m_state[6] += g;
    m_state[7] += h;
}

void SHA256::update(const uint8_t* data, size_t len) {
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

void SHA256::final(uint8_t hash[32]) {
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
    for (int b = 0; b < 8; ++b) {
        m_buffer[63 - b] = static_cast<uint8_t>((m_bit_len >> (b * 8)) & 0xFF);
    }
    transform(m_buffer);

    for (int j = 0; j < 8; ++j) {
        uint32_t s = m_state[j];
        hash[j * 4]     = static_cast<uint8_t>((s >> 24) & 0xFF);
        hash[j * 4 + 1] = static_cast<uint8_t>((s >> 16) & 0xFF);
        hash[j * 4 + 2] = static_cast<uint8_t>((s >> 8) & 0xFF);
        hash[j * 4 + 3] = static_cast<uint8_t>(s & 0xFF);
    }

    wipe();
}

} // namespace rfs
