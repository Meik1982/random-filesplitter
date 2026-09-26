#ifndef RFS_PROGRESS_HPP
#define RFS_PROGRESS_HPP

#include <iostream>
#include <iomanip>
#include <string>
#include <chrono>
#include <cstdint>

namespace rfs {

class ProgressBar {
public:
    ProgressBar(const std::string& taskName, uint64_t totalBytes, bool silent = false)
        : m_taskName(taskName), m_totalBytes(totalBytes), m_silent(silent) {
        m_startTime = std::chrono::steady_clock::now();
        m_lastUpdateTime = m_startTime;
    }

    void finish(uint64_t currentBytes) {
        if (m_silent) return;
        update(currentBytes, true);
    }

    void update(uint64_t currentBytes, bool force = false) {
        if (m_silent || m_finished) return;
        auto now = std::chrono::steady_clock::now();
        auto timeSinceLastUpdate = std::chrono::duration_cast<std::chrono::milliseconds>(now - m_lastUpdateTime).count();

        if (!force && timeSinceLastUpdate < 80 && currentBytes < m_totalBytes) {
            return;
        }
        m_lastUpdateTime = now;

        double progress = (m_totalBytes > 0) ? (static_cast<double>(currentBytes) / m_totalBytes) : 1.0;
        if (progress > 1.0) progress = 1.0;

        auto totalDurationMs = std::chrono::duration_cast<std::chrono::milliseconds>(now - m_startTime).count();
        double speedMBs = 0.0;
        if (totalDurationMs > 50) {
            speedMBs = (static_cast<double>(currentBytes) / (1024.0 * 1024.0)) / (totalDurationMs / 1000.0);
        }

        const int barWidth = 30;
        int pos = static_cast<int>(barWidth * progress);

        std::cout << char(13) << '[' << m_taskName << "] [";
        for (int i = 0; i < barWidth; ++i) {
            if (i < pos) std::cout << '=';
            else if (i == pos) std::cout << '>';
            else std::cout << ' ';
        }
        std::cout << "] " << std::fixed << std::setprecision(1) << (progress * 100.0) << "% ("
                  << speedMBs << " MB/s)    " << std::flush;

        if (force || currentBytes >= m_totalBytes) {
            m_finished = true;
            std::cout << std::endl;
        }
    }

private:
    std::string m_taskName;
    uint64_t m_totalBytes;
    bool m_silent;
    bool m_finished = false;
    std::chrono::steady_clock::time_point m_startTime;
    std::chrono::steady_clock::time_point m_lastUpdateTime;
};

} // namespace rfs

#endif // RFS_PROGRESS_HPP
