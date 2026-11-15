#include "logger.hpp"
#include <chrono>
#include <ctime>
#include <iomanip>
#include <sstream>

namespace gw {

Logger& Logger::instance() {
    static Logger instance;
    return instance;
}

Logger::Logger() noexcept
    : level_(LogLevel::INFO), outputStream_(&std::cout) {
}

void Logger::setLevel(LogLevel level) noexcept {
    std::lock_guard<std::mutex> lock(mutex_);
    level_ = level;
}

LogLevel Logger::getLevel() const noexcept {
    std::lock_guard<std::mutex> lock(mutex_);
    return level_;
}

bool Logger::isEnabled(LogLevel level) const noexcept {
    std::lock_guard<std::mutex> lock(mutex_);
    return static_cast<int>(level) >= static_cast<int>(level_);
}

void Logger::setOutputStream(std::ostream* stream) noexcept {
    std::lock_guard<std::mutex> lock(mutex_);
    outputStream_ = (stream != nullptr) ? stream : &std::cout;
}

static std::string currentTimestamp() {
    using namespace std::chrono;
    auto now = system_clock::now();
    auto ms = duration_cast<milliseconds>(now.time_since_epoch()) % 1000;
    auto timer = system_clock::to_time_t(now);

    std::tm bt{};
#if defined(_MSC_VER)
    localtime_s(&bt, &timer);
#elif defined(__unix__) || defined(__linux__) || defined(__APPLE__)
    localtime_r(&timer, &bt);
#else
    std::tm* tm_ptr = std::localtime(&timer);
    if (tm_ptr) {
        bt = *tm_ptr;
    }
#endif

    std::ostringstream oss;
    oss << std::put_time(&bt, "%Y-%m-%d %H:%M:%S")
        << '.' << std::setfill('0') << std::setw(3) << ms.count();
    return oss.str();
}

void Logger::log(LogLevel level, const std::string& module, const std::string& message) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (static_cast<int>(level) < static_cast<int>(level_)) {
        return;
    }

    std::string ts = currentTimestamp();
    *outputStream_ << '[' << ts << "] ["
                   << logLevelToString(level) << "] ["
                   << std::left << std::setw(6) << module << "] "
                   << message << std::endl;
}

void Logger::hexDump(LogLevel level, const std::string& module,
                     const std::string& label, const uint8_t* data, size_t length) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (static_cast<int>(level) < static_cast<int>(level_)) {
        return;
    }

    std::string ts = currentTimestamp();
    std::ostringstream hexStream;
    hexStream << std::hex << std::uppercase << std::setfill('0');

    for (size_t i = 0; i < length; ++i) {
        if (i > 0) {
            hexStream << ' ';
        }
        hexStream << std::setw(2) << static_cast<int>(data[i]);
    }

    *outputStream_ << '[' << ts << "] ["
                   << logLevelToString(level) << "] ["
                   << std::left << std::setw(6) << module << "] "
                   << label << ": " << hexStream.str()
                   << " (" << std::dec << length << " bytes)" << std::endl;
}

} // namespace gw
