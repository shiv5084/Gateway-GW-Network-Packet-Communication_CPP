#ifndef GW_LOGGER_HPP
#define GW_LOGGER_HPP

#include <string>
#include <mutex>
#include <cstdint>
#include <cstddef>
#include <iostream>

namespace gw {

#if defined(ERROR)
#undef ERROR
#endif

/**
 * @brief Log severity levels.
 */
enum class LogLevel {
    DEBUG,
    INFO,
    WARN,
    ERROR
};

/**
 * @brief Convert LogLevel enum to fixed-width string.
 */
inline const char* logLevelToString(LogLevel level) noexcept {
    switch (level) {
        case LogLevel::DEBUG: return "DEBUG";
        case LogLevel::INFO:  return "INFO ";
        case LogLevel::WARN:  return "WARN ";
        case LogLevel::ERROR: return "ERROR";
        default:              return "UNKWN";
    }
}

/**
 * @brief Thread-safe structured Logger singleton.
 *
 * Implements Singleton pattern (GoF Creational).
 * Follows Rule of Five: private constructor, all copy and move operations deleted.
 */
class Logger {
public:
    /**
     * @brief Access the global singleton Logger instance.
     */
    static Logger& instance();

    // Rule of Five: non-copyable, non-movable singleton
    ~Logger() = default;
    Logger(const Logger&) = delete;
    Logger& operator=(const Logger&) = delete;
    Logger(Logger&&) = delete;
    Logger& operator=(Logger&&) = delete;

    /**
     * @brief Set minimum logging severity threshold.
     */
    void setLevel(LogLevel level) noexcept;

    /**
     * @brief Get current minimum logging severity threshold.
     */
    LogLevel getLevel() const noexcept;

    /**
     * @brief Check if a log level is currently enabled.
     */
    bool isEnabled(LogLevel level) const noexcept;

    /**
     * @brief Output a formatted structured log line.
     */
    void log(LogLevel level, const std::string& module, const std::string& message);

    /**
     * @brief Output byte buffer as formatted hexadecimal bytes.
     */
    void hexDump(LogLevel level, const std::string& module,
                 const std::string& label, const uint8_t* data, size_t length);

    /**
     * @brief Redirect log output stream (defaults to std::cout).
     */
    void setOutputStream(std::ostream* stream) noexcept;

private:
    Logger() noexcept;

    LogLevel level_;
    std::ostream* outputStream_;
    mutable std::mutex mutex_;
};

} // namespace gw

#endif // GW_LOGGER_HPP
