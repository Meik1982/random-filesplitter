#include "rfs/splitter.hpp"
#include "rfs/chacha20.hpp"
#include "rfs/sha256.hpp"
#include "rfs/entropy.hpp"
#include "rfs/progress.hpp"
#include "rfs/types.hpp"

#include <iostream>
#include <fstream>
#include <vector>
#include <thread>
#include <mutex>
#include <condition_variable>
#include <chrono>
#include <cstring>
#include <algorithm>
#include <sys/stat.h>

#if defined(__AVX2__)
#include <immintrin.h>
#endif

#if defined(__linux__)
#include <fcntl.h>
#include <unistd.h>
#if defined(__GLIBCXX__)
#include <ext/stdio_filebuf.h>
#endif
#endif

namespace rfs {

namespace {

bool fileExists(const std::string& path) {
    struct stat buffer;
    return (stat(path.c_str(), &buffer) == 0);
}

// ============================================================================
// Asynchroner I/O & Hash Worker (Zero-Copy Swap Double-Buffering)
// ============================================================================
class SplitPipelineWorker {
public:
    SplitPipelineWorker(std::ofstream& f1, std::ofstream& f2, SHA256& hasher)
        : m_f1(f1), m_f2(f2), m_hasher(hasher), m_busy(false), m_hasWork(false),
          m_stop(false), m_ioError(false) {
        m_thread = std::thread(&SplitPipelineWorker::workerLoop, this);
    }

    ~SplitPipelineWorker() {
        finish();
    }

    bool submit(const char* cr1, const char* cr2, const char* plain, size_t size) {
        std::unique_lock<std::mutex> lock(m_mutex);
        m_cvDone.wait(lock, [this]() { return !m_busy; });

        if (m_ioError) return false;

        if (m_buf1.size() < size) {
            m_buf1.resize(size);
            m_buf2.resize(size);
            m_plain.resize(size);
        }
        std::memcpy(m_buf1.data(), cr1, size);
        std::memcpy(m_buf2.data(), cr2, size);
        std::memcpy(m_plain.data(), plain, size);
        m_size = size;

        m_busy = true;
        m_hasWork = true;
        m_cvWork.notify_one();
        return true;
    }

    bool waitComplete() {
        std::unique_lock<std::mutex> lock(m_mutex);
        m_cvDone.wait(lock, [this]() { return !m_busy; });
        return !m_ioError;
    }

    bool finish() {
        if (m_stop) return !m_ioError;
        waitComplete();
        {
            std::lock_guard<std::mutex> lock(m_mutex);
            m_stop = true;
            m_hasWork = true;
            m_cvWork.notify_one();
        }
        if (m_thread.joinable()) {
            m_thread.join();
        }
        secure_wipe_memory(m_buf1.data(), m_buf1.size());
        secure_wipe_memory(m_buf2.data(), m_buf2.size());
        secure_wipe_memory(m_plain.data(), m_plain.size());
        secure_wipe_memory(m_work1.data(), m_work1.size());
        secure_wipe_memory(m_work2.data(), m_work2.size());
        secure_wipe_memory(m_workPlain.data(), m_workPlain.size());
        return !m_ioError;
    }

private:
    void workerLoop() {
        while (true) {
            size_t workSize = 0;
            {
                std::unique_lock<std::mutex> lock(m_mutex);
                m_cvWork.wait(lock, [this]() { return m_hasWork; });
                if (m_stop) break;

                // O(1) Zero-Copy Swap der Puffer ohne Re-Allokation
                std::swap(m_work1, m_buf1);
                std::swap(m_work2, m_buf2);
                std::swap(m_workPlain, m_plain);
                workSize = m_size;
                m_hasWork = false;
            }

            m_hasher.update(reinterpret_cast<const uint8_t*>(m_workPlain.data()), workSize);

            m_f1.write(m_work1.data(), workSize);
            m_f2.write(m_work2.data(), workSize);

            bool ok = m_f1.good() && m_f2.good();

            secure_wipe_memory(m_workPlain.data(), workSize);

            {
                std::lock_guard<std::mutex> lock(m_mutex);
                if (!ok) m_ioError = true;
                m_busy = false;
                m_cvDone.notify_all();
            }
        }
    }

    std::ofstream& m_f1;
    std::ofstream& m_f2;
    SHA256& m_hasher;
    std::vector<char> m_buf1;
    std::vector<char> m_buf2;
    std::vector<char> m_plain;
    std::vector<char> m_work1;
    std::vector<char> m_work2;
    std::vector<char> m_workPlain;
    size_t m_size = 0;
    bool m_busy;
    bool m_hasWork;
    bool m_stop;
    bool m_ioError;
    std::mutex m_mutex;
    std::condition_variable m_cvWork;
    std::condition_variable m_cvDone;
    std::thread m_thread;
};

class RestorePipelineWorker {
public:
    RestorePipelineWorker(std::ofstream& out)
        : m_out(out), m_busy(false), m_hasWork(false), m_stop(false), m_ioError(false) {
        m_thread = std::thread(&RestorePipelineWorker::workerLoop, this);
    }

    ~RestorePipelineWorker() {
        finish();
    }

    bool submit(const char* data, size_t size) {
        std::unique_lock<std::mutex> lock(m_mutex);
        m_cvDone.wait(lock, [this]() { return !m_busy; });

        if (m_ioError) return false;

        if (m_buf.size() < size) {
            m_buf.resize(size);
        }
        std::memcpy(m_buf.data(), data, size);
        m_size = size;

        m_busy = true;
        m_hasWork = true;
        m_cvWork.notify_one();
        return true;
    }

    bool waitComplete() {
        std::unique_lock<std::mutex> lock(m_mutex);
        m_cvDone.wait(lock, [this]() { return !m_busy; });
        return !m_ioError;
    }

    bool finish() {
        if (m_stop) return !m_ioError;
        waitComplete();
        {
            std::lock_guard<std::mutex> lock(m_mutex);
            m_stop = true;
            m_hasWork = true;
            m_cvWork.notify_one();
        }
        if (m_thread.joinable()) {
            m_thread.join();
        }
        secure_wipe_memory(m_buf.data(), m_buf.size());
        secure_wipe_memory(m_work.data(), m_work.size());
        return !m_ioError;
    }

private:
    void workerLoop() {
        while (true) {
            size_t workSize = 0;
            {
                std::unique_lock<std::mutex> lock(m_mutex);
                m_cvWork.wait(lock, [this]() { return m_hasWork; });
                if (m_stop) break;

                // O(1) Zero-Copy Swap der Puffer ohne Re-Allokation
                std::swap(m_work, m_buf);
                workSize = m_size;
                m_hasWork = false;
            }

            m_out.write(m_work.data(), workSize);
            bool ok = m_out.good();
            secure_wipe_memory(m_work.data(), workSize);

            {
                std::lock_guard<std::mutex> lock(m_mutex);
                if (!ok) m_ioError = true;
                m_busy = false;
                m_cvDone.notify_all();
            }
        }
    }

    std::ofstream& m_out;
    std::vector<char> m_buf;
    std::vector<char> m_work;
    size_t m_size = 0;
    bool m_busy;
    bool m_hasWork;
    bool m_stop;
    bool m_ioError;
    std::mutex m_mutex;
    std::condition_variable m_cvWork;
    std::condition_variable m_cvDone;
    std::thread m_thread;
};

class SequentialInputStream {
public:
    explicit SequentialInputStream(const std::string& path) {
#if defined(__linux__) && defined(__GLIBCXX__)
        m_fd = open(path.c_str(), O_RDONLY | O_CLOEXEC);
        if (m_fd >= 0) {
            posix_fadvise(m_fd, 0, 0, POSIX_FADV_SEQUENTIAL);
            m_filebuf = std::make_unique<__gnu_cxx::stdio_filebuf<char>>(m_fd, std::ios::in | std::ios::binary);
            m_stream = std::make_unique<std::istream>(m_filebuf.get());
        }
#else
        auto s = std::make_unique<std::ifstream>(path, std::ios::binary);
        if (s->is_open()) {
            m_stream = std::move(s);
        }
#endif
    }

    ~SequentialInputStream() {
#if defined(__linux__) && defined(__GLIBCXX__)
        m_stream.reset();
        m_filebuf.reset();
        if (m_fd >= 0) {
            close(m_fd);
        }
#endif
    }

    bool is_open() const { return m_stream && m_stream->good(); }
    explicit operator bool() const { return is_open(); }
    std::istream& get() { return *m_stream; }

private:
#if defined(__linux__) && defined(__GLIBCXX__)
    int m_fd = -1;
    std::unique_ptr<__gnu_cxx::stdio_filebuf<char>> m_filebuf;
#endif
    std::unique_ptr<std::istream> m_stream;
};

} // namespace

void displayVersion() {
    std::cout << APP_NAME << " version " << APP_VERSION
              << " (Format: " << FORMAT_TAG
#if defined(__AVX2__)
              << ", AVX2 SIMD 8-Block)"
#else
              << ", Portable 64-Bit)"
#endif
              << "\n"
              << "Copyright (c) 2026 Meik Augenblick (LGPL v3)\n";
}

void displayHelp() {
    std::cout << "\n============================================================\n"
              << " RFS - Random File Splitter v" << APP_VERSION << " (" << FORMAT_TAG << " Edition)\n"
              << "============================================================\n"
              << " Verwendung:\n"
              << "   Splitten:         rfs <Datei> [-B <Puffer>]\n"
              << "   Wiederherstellen: rfs <Datei.rfs1> <Datei.rfs2> [-o <Ziel>] [-f] [-B <Puffer>]\n"
              << "   Integritaetstest: rfs --verify <Datei.rfs1> <Datei.rfs2> [-B <Puffer>]\n"
              << "   Datei-Entropie:   rfs -a <Datei>  (oder --analyze / --file-entropy)\n"
              << "   System-Entropie:  rfs --entropy-test\n"
              << "   Hardware-Test:    rfs --benchmark\n\n"
              << " Optionen:\n"
              << "   -a, --analyze <Pfad> Datei auf Entropie und kryptografische Guete pruefen\n"
              << "   -B, --block-size <G> Puffergroesse (z.B. 64K, 1M, 4M, 16M; Standard: 4M)\n"
              << "   -o, --output <Pfad>  Zielpfad fuer wiederhergestellte Datei\n"
              << "   -f, --force          Bestehende Zieldatei ohne Rueckfrage ueberschreiben\n"
              << "   -v, --verify         Nur Integritaet pruefen (keine Datei schreiben)\n"
              << "   -e, --entropy-test   Zweiphasige Entropie- & NIST-Kryptoanalyse\n"
              << "   -b, --benchmark      Hardware-Durchsatzmessung (SIMD & Pipeline)\n"
              << "   -V, --version        Versionsinformationen anzeigen\n"
              << "   -h, --help           Diese Hilfe anzeigen\n\n";
}

int splitFile(const SplitOptions& opts) {
    SequentialInputStream inStream(opts.inputPath);
    if (!inStream) {
        std::cerr << "Fehler: Quelldatei '" << opts.inputPath << "' konnte nicht geoeffnet werden.\n";
        return 1;
    }
    std::istream& inputFile = inStream.get();

    std::string cr1FileName = opts.inputPath + ".rfs1";
    std::string cr2FileName = opts.inputPath + ".rfs2";
    std::ofstream cr1File(cr1FileName, std::ios::binary);
    std::ofstream cr2File(cr2FileName, std::ios::binary);

    if (!cr1File || !cr2File) {
        std::cerr << "Fehler: Zieldateien konnten nicht erstellt werden (Schreibrechte pruefen).\n";
        return 1;
    }

    inputFile.seekg(0, std::ios::end);
    uint64_t originalSize = static_cast<uint64_t>(inputFile.tellg());
    inputFile.seekg(0, std::ios::beg);

    uint8_t masterKey[32];
    uint8_t masterNonce[12];
    UniversalEntropyHarvester::harvestSeed(masterKey, masterNonce);
    ChaCha20RNG rng(masterKey, masterNonce);

    SHA256 hasher;

    const size_t BUFFER_SIZE = opts.blockSize;
    std::vector<char> buffer(BUFFER_SIZE);
    std::vector<char> cr1Buf(BUFFER_SIZE);
    std::vector<char> cr2Buf(BUFFER_SIZE);

    ProgressBar progress("Splitting", originalSize, opts.silent);
    uint64_t totalBytesRead = 0;

    SplitPipelineWorker worker(cr1File, cr2File, hasher);

    while (inputFile) {
        inputFile.read(buffer.data(), BUFFER_SIZE);
        std::streamsize bytesRead = inputFile.gcount();
        if (bytesRead <= 0) break;

        totalBytesRead += bytesRead;

        rng.generateBytes(reinterpret_cast<uint8_t*>(cr2Buf.data()), bytesRead);

        size_t offset = 0;
#if defined(__AVX2__)
        while (offset + 32 <= static_cast<size_t>(bytesRead)) {
            __m256i s = _mm256_loadu_si256(reinterpret_cast<const __m256i*>(buffer.data() + offset));
            __m256i r = _mm256_loadu_si256(reinterpret_cast<const __m256i*>(cr2Buf.data() + offset));
            __m256i d = _mm256_xor_si256(s, r);
            _mm256_storeu_si256(reinterpret_cast<__m256i*>(cr1Buf.data() + offset), d);
            offset += 32;
        }
#endif
        while (offset + 8 <= static_cast<size_t>(bytesRead)) {
            *reinterpret_cast<uint64_t*>(cr1Buf.data() + offset) =
                *reinterpret_cast<const uint64_t*>(buffer.data() + offset) ^
                *reinterpret_cast<const uint64_t*>(cr2Buf.data() + offset);
            offset += 8;
        }
        for (size_t i = offset; i < static_cast<size_t>(bytesRead); ++i) {
            cr1Buf[i] = static_cast<char>(static_cast<uint8_t>(buffer[i]) ^ static_cast<uint8_t>(cr2Buf[i]));
        }

        if (!worker.submit(cr1Buf.data(), cr2Buf.data(), buffer.data(), bytesRead)) {
            std::cerr << "\nFehler: Schreibfehler auf Zieldateien (Datentraeger voll?).\n";
            return 1;
        }

        progress.update(totalBytesRead);
    }

    if (!worker.finish()) {
        std::cerr << "\nFehler: Abschliessender Schreibvorgang fehlgeschlagen.\n";
        return 1;
    }

    progress.finish(totalBytesRead);

    // Stealth Padding (Zufallsrauschen)
    uint32_t paddingSize = rng.next_range_u32(1024, 102400);
    std::vector<char> padBuf1(paddingSize);
    std::vector<char> padBuf2(paddingSize);
    rng.generateBytes(reinterpret_cast<uint8_t*>(padBuf1.data()), paddingSize);
    rng.generateBytes(reinterpret_cast<uint8_t*>(padBuf2.data()), paddingSize);
    cr1File.write(padBuf1.data(), paddingSize);
    cr2File.write(padBuf2.data(), paddingSize);

    // SHA-256 Hash berechnen
    uint8_t hash[32];
    hasher.final(hash);

    // Little-Endian Dateigröße
    uint8_t sizeBytes[8];
    write_u64_le(sizeBytes, originalSize);

    // ========================================================================
    // RFS2 Footer (44 Bytes, ge-XORt für 100% Plausible Deniability)
    // 4B Magic ("RFS2") + 32B SHA-256 Hash + 8B Original Size
    // ========================================================================
    for (size_t i = 0; i < MAGIC_SIZE; ++i) {
        uint8_t rnd = rng.next_u8();
        cr1File.put(static_cast<char>(RFS2_MAGIC_BYTES[i] ^ rnd));
        cr2File.put(static_cast<char>(rnd));
    }

    for (size_t i = 0; i < HASH_SIZE; ++i) {
        uint8_t rnd = rng.next_u8();
        cr1File.put(static_cast<char>(hash[i] ^ rnd));
        cr2File.put(static_cast<char>(rnd));
    }

    for (size_t i = 0; i < SIZE_HEADER_SIZE; ++i) {
        uint8_t rnd = rng.next_u8();
        cr1File.put(static_cast<char>(sizeBytes[i] ^ rnd));
        cr2File.put(static_cast<char>(rnd));
    }

    cr1File.flush();
    cr2File.flush();
    if (!cr1File.good() || !cr2File.good()) {
        std::cerr << "Fehler: Metadaten-Footer konnte nicht vollstaendig geschrieben werden.\n";
        return 1;
    }

    // Sichere Speicherhygiene
    secure_wipe_memory(buffer.data(), buffer.size());
    secure_wipe_memory(cr1Buf.data(), cr1Buf.size());
    secure_wipe_memory(cr2Buf.data(), cr2Buf.size());
    secure_wipe_memory(padBuf1.data(), padBuf1.size());
    secure_wipe_memory(padBuf2.data(), padBuf2.size());
    secure_wipe_memory(masterKey, sizeof(masterKey));
    secure_wipe_memory(masterNonce, sizeof(masterNonce));
    secure_wipe_memory(hash, sizeof(hash));
    secure_wipe_memory(sizeBytes, sizeof(sizeBytes));

    if (!opts.silent) {
        std::cout << "Erfolg: Datei erfolgreich im Format " << FORMAT_TAG << " geteilt.\n"
                  << "  Teil 1: " << cr1FileName << "\n"
                  << "  Teil 2: " << cr2FileName << "\n";
    }
    return 0;
}

int restoreOrVerifyFile(const RestoreOptions& opts) {
    std::string fileRfs1 = opts.file1;
    std::string fileRfs2 = opts.file2;

    if (fileRfs1.find(".rfs2") != std::string::npos && fileRfs2.find(".rfs1") != std::string::npos) {
        std::swap(fileRfs1, fileRfs2);
    }

    SequentialInputStream inCr1(fileRfs1);
    SequentialInputStream inCr2(fileRfs2);
    if (!inCr1 || !inCr2) {
        std::cerr << "Fehler: Mindestens eine Eingabedatei konnte nicht geoeffnet werden.\n";
        return 1;
    }
    std::istream& cr1 = inCr1.get();
    std::istream& cr2 = inCr2.get();

    cr1.seekg(0, std::ios::end);
    cr2.seekg(0, std::ios::end);
    uint64_t len1 = static_cast<uint64_t>(cr1.tellg());
    uint64_t len2 = static_cast<uint64_t>(cr2.tellg());

    if (len1 < FOOTER_SIZE || len2 < FOOTER_SIZE) {
        std::cerr << "Fehler: Ungueltige RFS-Dateien (Dateigroesse kleiner als Footer-Header).\n";
        return 1;
    }
    if (len1 != len2) {
        std::cerr << "Fehler: Dateigroessen stimmen nicht ueberein (Beschaedigt oder unvollstaendig).\n";
        return 1;
    }

    // Footer lesen (letzte 44 Bytes)
    cr1.seekg(-static_cast<std::streamoff>(FOOTER_SIZE), std::ios::end);
    cr2.seekg(-static_cast<std::streamoff>(FOOTER_SIZE), std::ios::end);

    uint8_t footerXor[FOOTER_SIZE];
    for (size_t i = 0; i < FOOTER_SIZE; ++i) {
        char b1, b2;
        cr1.get(b1);
        cr2.get(b2);
        footerXor[i] = static_cast<uint8_t>(b1) ^ static_cast<uint8_t>(b2);
    }

    // 1. Magic-Tag Validierung (Bytes 0..3)
    if (std::memcmp(footerXor, RFS2_MAGIC_BYTES, MAGIC_SIZE) != 0) {
        std::cerr << "Fehler: Ungueltige oder nicht zusammengehoerige RFS2-Dateien (Magic-Tag Mismatch)!\n"
                  << "Hinweis: Pruefen Sie, ob es sich um die korrekten zusammengehoerigen Teile handelt.\n";
        secure_wipe_memory(footerXor, sizeof(footerXor));
        return 1;
    }

    // 2. Hash & Size extrahieren
    uint8_t expectedHash[HASH_SIZE];
    std::memcpy(expectedHash, footerXor + MAGIC_SIZE, HASH_SIZE);

    uint64_t originalSize = read_u64_le(footerXor + MAGIC_SIZE + HASH_SIZE);
    secure_wipe_memory(footerXor, sizeof(footerXor));

    if (originalSize > len1 - FOOTER_SIZE) {
        std::cerr << "Fehler: Rekonstruierte Dateigroesse ist unplausibel. Dateien sind beschaedigt.\n";
        secure_wipe_memory(expectedHash, sizeof(expectedHash));
        return 1;
    }

    std::string outName;
    if (!opts.outputPath.empty()) {
        outName = opts.outputPath;
    } else {
        outName = fileRfs1;
        if (outName.size() > 5 && outName.substr(outName.size() - 5) == ".rfs1") {
            outName = outName.substr(0, outName.size() - 5);
        } else if (outName.size() > 5 && outName.substr(outName.size() - 5) == ".rfs2") {
            outName = outName.substr(0, outName.size() - 5);
        } else {
            outName += ".restored";
        }
    }

    // Überschreibschutz
    if (!opts.verifyOnly && fileExists(outName) && !opts.force) {
        std::cerr << "Fehler: Zieldatei '" << outName << "' existiert bereits.\n"
                  << "Verwenden Sie -f oder --force, um das Ueberschreiben zu erzwingen.\n";
        secure_wipe_memory(expectedHash, sizeof(expectedHash));
        return 1;
    }

    std::unique_ptr<std::ofstream> outFile;
    if (!opts.verifyOnly) {
        outFile.reset(new std::ofstream(outName, std::ios::binary));
        if (!outFile || !outFile->good()) {
            std::cerr << "Fehler: Ausgabedatei '" << outName << "' kann nicht geschrieben werden.\n";
            secure_wipe_memory(expectedHash, sizeof(expectedHash));
            return 1;
        }
    }

    cr1.seekg(0, std::ios::beg);
    cr2.seekg(0, std::ios::beg);

    SHA256 hasher;
    const size_t BUFFER_SIZE = opts.blockSize;
    std::vector<char> b1(BUFFER_SIZE);
    std::vector<char> b2(BUFFER_SIZE);
    std::vector<char> bOut(BUFFER_SIZE);
    uint64_t processed = 0;

    std::string taskLabel = opts.verifyOnly ? "Verifying" : "Restoring";
    ProgressBar progress(taskLabel, originalSize, opts.silent);

    std::unique_ptr<RestorePipelineWorker> worker;
    if (!opts.verifyOnly && outFile) {
        worker.reset(new RestorePipelineWorker(*outFile));
    }

    while (processed < originalSize) {
        uint64_t toRead = std::min(static_cast<uint64_t>(BUFFER_SIZE), originalSize - processed);
        cr1.read(b1.data(), toRead);
        cr2.read(b2.data(), toRead);

        size_t offset = 0;
#if defined(__AVX2__)
        while (offset + 32 <= toRead) {
            __m256i s = _mm256_loadu_si256(reinterpret_cast<const __m256i*>(b1.data() + offset));
            __m256i r = _mm256_loadu_si256(reinterpret_cast<const __m256i*>(b2.data() + offset));
            __m256i d = _mm256_xor_si256(s, r);
            _mm256_storeu_si256(reinterpret_cast<__m256i*>(bOut.data() + offset), d);
            offset += 32;
        }
#endif
        while (offset + 8 <= toRead) {
            *reinterpret_cast<uint64_t*>(bOut.data() + offset) =
                *reinterpret_cast<const uint64_t*>(b1.data() + offset) ^
                *reinterpret_cast<const uint64_t*>(b2.data() + offset);
            offset += 8;
        }
        for (size_t i = offset; i < toRead; ++i) {
            bOut[i] = static_cast<char>(static_cast<uint8_t>(b1[i]) ^ static_cast<uint8_t>(b2[i]));
        }

        hasher.update(reinterpret_cast<const uint8_t*>(bOut.data()), toRead);

        if (worker) {
            if (!worker->submit(bOut.data(), toRead)) {
                std::cerr << "\nFehler: Schreibfehler bei der Wiederherstellung (Datentraeger voll?).\n";
                return 1;
            }
        }

        processed += toRead;
        progress.update(processed);
    }

    if (worker && !worker->finish()) {
        std::cerr << "\nFehler: Abschluss des Schreibvorgangs fehlgeschlagen.\n";
        return 1;
    }

    progress.finish(processed);

    if (outFile) {
        outFile->flush();
    }

    uint8_t calculatedHash[32];
    hasher.final(calculatedHash);

    bool hashMatch = (std::memcmp(calculatedHash, expectedHash, 32) == 0);

    secure_wipe_memory(b1.data(), b1.size());
    secure_wipe_memory(b2.data(), b2.size());
    secure_wipe_memory(bOut.data(), bOut.size());
    secure_wipe_memory(calculatedHash, sizeof(calculatedHash));
    secure_wipe_memory(expectedHash, sizeof(expectedHash));

    if (hashMatch) {
        if (!opts.silent) {
            if (opts.verifyOnly) {
                std::cout << "Erfolg: Integritaetstest bestanden! Die Teile sind unversehrt und gueltig.\n"
                          << "  Format: " << FORMAT_TAG << " (Geprueft via Magic-Tag & SHA-256)\n"
                          << "  Original-Dateigroesse: " << originalSize << " Bytes\n"
                          << "  SHA-256 Hash: OK\n";
            } else {
                std::cout << "Erfolg: Datei erfolgreich wiederhergestellt -> " << outName << "\n"
                          << "Integritaet: Magic-Tag & SHA-256 Hash geprueft und gueltig (OK).\n";
            }
        }
        return 0;
    } else {
        std::cerr << "WARNUNG: Integritaetsfehler! SHA-256 Pruefsumme stimmt nicht ueberein.\n"
                  << "Die Datei ist moeglicherweise beschaedigt oder manipuliert.\n";
        return 2;
    }
}

int runBenchmark() {
    std::cout << "\n============================================================\n"
              << " RFS Hardware-Benchmark (Multi-Threading & AVX2 Durchsatz)\n"
              << "============================================================\n\n";

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
    std::string simdLbl = "AVX2 SIMD (8 Blöcke / 512-Bit pro Durchlauf)";
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

    secure_wipe_memory(key, sizeof(key));
    secure_wipe_memory(nonce, sizeof(nonce));
    secure_wipe_memory(finalHash, sizeof(finalHash));

    std::cout << "Fazit: Ihre CPU liefert mit " << simdLbl << " ca. "
              << std::fixed << std::setprecision(1) << chachaSpeedMB << " MB/s Krypto-Durchsatz.\n"
              << "Damit ist sichergestellt, dass RFS mit maximaler Pipeline-Effizienz arbeitet.\n\n";
    return 0;
}

} // namespace rfs
