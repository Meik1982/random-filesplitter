#ifndef RFS_TYPES_HPP
#define RFS_TYPES_HPP

#include <cstdint>
#include <cstddef>
#include <cstring>
#include <string>

#if defined(_WIN32)
#include <windows.h>
#endif

namespace rfs {

constexpr const char* APP_NAME = "rfs";
constexpr const char* APP_VERSION = "2.0.0";
constexpr const char* FORMAT_TAG = "RFS2";

constexpr size_t MAGIC_SIZE = 4;
constexpr size_t HASH_SIZE = 32;
constexpr size_t SIZE_HEADER_SIZE = 8;
constexpr size_t FOOTER_SIZE = MAGIC_SIZE + HASH_SIZE + SIZE_HEADER_SIZE; // 44 Bytes

const uint8_t RFS2_MAGIC_BYTES[4] = { 'R', 'F', 'S', '2' };

// ============================================================================
// Krypto-Hygiene: Sichere Speicherlöschung gegen Dead-Store-Elimination
// ============================================================================
inline void secure_wipe_memory(void* ptr, size_t size) {
    if (!ptr || size == 0) return;
#if defined(_WIN32)
    SecureZeroMemory(ptr, size);
#elif defined(__GLIBC__) && (__GLIBC__ > 2 || (__GLIBC__ == 2 && __GLIBC_MINOR__ >= 25))
    explicit_bzero(ptr, size);
#else
    volatile uint8_t* p = static_cast<volatile uint8_t*>(ptr);
    while (size--) {
        *p++ = 0;
    }
#if defined(__GNUC__) || defined(__clang__)
    __asm__ __volatile__("" : : "r"(ptr) : "memory");
#endif
#endif
}

// ============================================================================
// Endianness-sichere Little-Endian Serialisierung
// ============================================================================
inline void write_u64_le(uint8_t dest[8], uint64_t val) {
    for (int i = 0; i < 8; ++i) {
        dest[i] = static_cast<uint8_t>((val >> (i * 8)) & 0xFF);
    }
}

inline uint64_t read_u64_le(const uint8_t src[8]) {
    uint64_t val = 0;
    for (int i = 0; i < 8; ++i) {
        val |= (static_cast<uint64_t>(src[i]) << (i * 8));
    }
    return val;
}

inline void write_u32_le(uint8_t dest[4], uint32_t val) {
    dest[0] = static_cast<uint8_t>(val & 0xFF);
    dest[1] = static_cast<uint8_t>((val >> 8) & 0xFF);
    dest[2] = static_cast<uint8_t>((val >> 16) & 0xFF);
    dest[3] = static_cast<uint8_t>((val >> 24) & 0xFF);
}

inline uint32_t read_u32_le(const uint8_t src[4]) {
    return static_cast<uint32_t>(src[0])
         | (static_cast<uint32_t>(src[1]) << 8)
         | (static_cast<uint32_t>(src[2]) << 16)
         | (static_cast<uint32_t>(src[3]) << 24);
}

} // namespace rfs

#endif // RFS_TYPES_HPP
