#ifndef RFS_SPLITTER_HPP
#define RFS_SPLITTER_HPP

#include <string>
#include "types.hpp"

namespace rfs {

struct SplitOptions {
    std::string inputPath;
    size_t blockSize = DEFAULT_BLOCK_SIZE;
    bool silent = false;
};

struct RestoreOptions {
    std::string file1;
    std::string file2;
    std::string outputPath;
    size_t blockSize = DEFAULT_BLOCK_SIZE;
    bool verifyOnly = false;
    bool force = false;
    bool silent = false;
};

int splitFile(const SplitOptions& opts);
int restoreOrVerifyFile(const RestoreOptions& opts);
int runBenchmark();
void displayHelp();
void displayVersion();

} // namespace rfs

#endif // RFS_SPLITTER_HPP
