// Dieses Programm wurde von Meik Augenblik unter der Lesser GNU General Public License (LGPL) geschrieben.

#include <iostream>
#include <fstream>
#include <string>
#include <random>
#include <cstdint>
#include <vector>
#include <cstring> // Für memset und memcmp

// --- Kompakte SHA-256 Implementierung ---
class SHA256 {
public:
    SHA256() { reset(); }
    void update(const uint8_t* data, size_t len) {
        for (size_t i = 0; i < len; ++i) {
            m_buffer[m_buffer_len++] = data[i];
            if (m_buffer_len == 64) {
                transform();
                m_bit_len += 512;
                m_buffer_len = 0;
            }
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
            transform();
            memset(m_buffer, 0, 56);
        }
        m_bit_len += m_buffer_len * 8;
        m_buffer[63] = m_bit_len; m_buffer[62] = m_bit_len >> 8;
        m_buffer[61] = m_bit_len >> 16; m_buffer[60] = m_bit_len >> 24;
        m_buffer[59] = m_bit_len >> 32; m_buffer[58] = m_bit_len >> 40;
        m_buffer[57] = m_bit_len >> 48; m_buffer[56] = m_bit_len >> 56;
        transform();
        for (int i = 0; i < 8; ++i) {
            uint32_t s = m_state[i];
            hash[i*4] = (s >> 24) & 0xff;
            hash[i*4+1] = (s >> 16) & 0xff;
            hash[i*4+2] = (s >> 8) & 0xff;
            hash[i*4+3] = s & 0xff;
        }
    }
private:
    uint32_t m_state[8]; uint8_t m_buffer[64]; uint32_t m_buffer_len; uint64_t m_bit_len;
    uint32_t rotr(uint32_t x, uint32_t n) { return (x >> n) | (x << (32 - n)); }
    uint32_t ch(uint32_t x, uint32_t y, uint32_t z) { return (x & y) ^ (~x & z); }
    uint32_t maj(uint32_t x, uint32_t y, uint32_t z) { return (x & y) ^ (x & z) ^ (y & z); }
    void transform() {
        uint32_t a, b, c, d, e, f, g, h, i, t1, t2, m[64];
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
        for (i = 0; i < 16; ++i)
            m[i] = (m_buffer[i*4] << 24) | (m_buffer[i*4+1] << 16) | (m_buffer[i*4+2] << 8) | (m_buffer[i*4+3]);
        for ( ; i < 64; ++i)
            m[i] = (rotr(m[i-2],17)^rotr(m[i-2],19)^(m[i-2]>>10)) + m[i-7] + (rotr(m[i-15],7)^rotr(m[i-15],18)^(m[i-15]>>3)) + m[i-16];
        a = m_state[0]; b = m_state[1]; c = m_state[2]; d = m_state[3]; e = m_state[4]; f = m_state[5]; g = m_state[6]; h = m_state[7];
        for (i = 0; i < 64; ++i) {
            t1 = h + (rotr(e,6)^rotr(e,11)^rotr(e,25)) + ch(e,f,g) + k[i] + m[i];
            t2 = (rotr(a,2)^rotr(a,13)^rotr(a,22)) + maj(a,b,c);
            h = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2;
        }
        m_state[0] += a; m_state[1] += b; m_state[2] += c; m_state[3] += d; m_state[4] += e; m_state[5] += f; m_state[6] += g; m_state[7] += h;
    }
    void reset() {
        m_state[0] = 0x6a09e667; m_state[1] = 0xbb67ae85; m_state[2] = 0x3c6ef372; m_state[3] = 0xa54ff53a;
        m_state[4] = 0x510e527f; m_state[5] = 0x9b05688c; m_state[6] = 0x1f83d9ab; m_state[7] = 0x5be0cd19;
        m_buffer_len = 0; m_bit_len = 0;
    }
};

void displayHelp() {
    std::cout << "\n [Hilfe]\n Verschlüsseln: rfs <Datei>\n Entschlüsseln: rfs <Datei.rfs1> <Datei.rfs2>\n\n";
}

int encryptFile(const std::string& inputFileName) {
    std::ifstream inputFile(inputFileName, std::ios::binary);
    if (!inputFile) return 1;

    std::string cr1FileName = inputFileName + ".rfs1";
    std::string cr2FileName = inputFileName + ".rfs2";
    std::ofstream cr1File(cr1FileName, std::ios::binary);
    std::ofstream cr2File(cr2FileName, std::ios::binary);

    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<uint16_t> dist(0, 255);
    SHA256 hasher;

    inputFile.seekg(0, std::ios::end);
    uint64_t originalSize = inputFile.tellg();
    inputFile.seekg(0, std::ios::beg);

    const size_t BUFFER_SIZE = 4 * 1024 * 1024;
    std::vector<char> buffer(BUFFER_SIZE), cr1Buf(BUFFER_SIZE), cr2Buf(BUFFER_SIZE);

    while (inputFile) {
        inputFile.read(buffer.data(), BUFFER_SIZE);
        std::streamsize bytesRead = inputFile.gcount();
        if (bytesRead == 0) break;

        hasher.update(reinterpret_cast<uint8_t*>(buffer.data()), bytesRead);

        for (std::streamsize i = 0; i < bytesRead; ++i) {
            uint8_t rnd = static_cast<uint8_t>(dist(gen));
            cr1Buf[i] = static_cast<char>(static_cast<uint8_t>(buffer[i]) ^ rnd);
            cr2Buf[i] = static_cast<char>(rnd);
        }
        cr1File.write(cr1Buf.data(), bytesRead);
        cr2File.write(cr2Buf.data(), bytesRead);
    }

    // Padding
    std::uniform_int_distribution<uint32_t> padDist(1024, 102400);
    uint32_t paddingSize = padDist(gen);
    for (uint32_t i = 0; i < paddingSize; ++i) {
        cr1File.put(static_cast<char>(dist(gen)));
        cr2File.put(static_cast<char>(dist(gen)));
    }

    // Hash schreiben (verschlüsselt)
    uint8_t hash[32];
    hasher.final(hash);
    for (int i = 0; i < 32; ++i) {
        uint8_t rnd = static_cast<uint8_t>(dist(gen));
        cr1File.put(static_cast<char>(hash[i] ^ rnd));
        cr2File.put(static_cast<char>(rnd));
    }

    // Größe schreiben (verschlüsselt)
    uint8_t* sizePtr = reinterpret_cast<uint8_t*>(&originalSize);
    for (int i = 0; i < 8; ++i) {
        uint8_t rnd = static_cast<uint8_t>(dist(gen));
        cr1File.put(static_cast<char>(sizePtr[i] ^ rnd));
        cr2File.put(static_cast<char>(rnd));
    }

    return 0;
}

int decryptFile(const std::string& cr1Name, const std::string& cr2Name) {
    std::ifstream cr1(cr1Name, std::ios::binary), cr2(cr2Name, std::ios::binary);
    if (!cr1 || !cr2) return 1;

    std::string outName = cr1Name.substr(0, cr1Name.size() - 5);
    
    // Größe lesen (letzte 8 Bytes)
    cr1.seekg(-8, std::ios::end); cr2.seekg(-8, std::ios::end);
    uint64_t originalSize = 0;
    uint8_t* sizePtr = reinterpret_cast<uint8_t*>(&originalSize);
    for (int i = 0; i < 8; ++i) {
        char b1, b2; cr1.get(b1); cr2.get(b2);
        sizePtr[i] = static_cast<uint8_t>(b1) ^ static_cast<uint8_t>(b2);
    }

    // Hash lesen (32 Bytes vor der Größe)
    cr1.seekg(-40, std::ios::end); cr2.seekg(-40, std::ios::end);
    uint8_t expectedHash[32];
    for (int i = 0; i < 32; ++i) {
        char b1, b2; cr1.get(b1); cr2.get(b2);
        expectedHash[i] = static_cast<uint8_t>(b1) ^ static_cast<uint8_t>(b2);
    }

    std::ofstream out(outName, std::ios::binary);
    cr1.seekg(0); cr2.seekg(0);
    SHA256 hasher;
    const size_t BS = 4 * 1024 * 1024;
    std::vector<char> b1(BS), b2(BS), bO(BS);
    uint64_t processed = 0;

    while (processed < originalSize) {
        uint64_t toRead = std::min((uint64_t)BS, originalSize - processed);
        cr1.read(b1.data(), toRead); cr2.read(b2.data(), toRead);
        for (std::streamsize i = 0; i < (std::streamsize)toRead; ++i)
            bO[i] = static_cast<char>(static_cast<uint8_t>(b1[i]) ^ static_cast<uint8_t>(b2[i]));
        
        hasher.update(reinterpret_cast<uint8_t*>(bO.data()), toRead);
        out.write(bO.data(), toRead);
        processed += toRead;
    }

    uint8_t calcHash[32];
    hasher.final(calcHash);
    if (std::memcmp(calcHash, expectedHash, 32) == 0) {
        std::cout << "Erfolg: Datei ist integer (Hash OK).\n";
    } else {
        std::cerr << "WARNUNG: Hash-Fehler! Datei korrupt oder manipuliert.\n";
    }
    return 0;
}

int main(int argc, char* argv[]) {
    if (argc == 2) return encryptFile(argv[1]);
    if (argc == 3) return decryptFile(argv[1], argv[2]);
    displayHelp();
    return 0;
}