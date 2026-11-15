#include "server_metrics.hpp"
#include "logger.hpp"
#include <sstream>

namespace gw {

ServerMetrics& ServerMetrics::instance() {
    static ServerMetrics instance;
    return instance;
}

void ServerMetrics::onRequestReceived() noexcept {
    totalRequests_.fetch_add(1, std::memory_order_relaxed);
}

void ServerMetrics::onPositiveResponse() noexcept {
    positiveResponses_.fetch_add(1, std::memory_order_relaxed);
}

void ServerMetrics::onNegativeResponse(FailureCode code) noexcept {
    switch (code) {
        case FailureCode::SourceAddrInvalid:
            negative0x01_.fetch_add(1, std::memory_order_relaxed);
            break;
        case FailureCode::TargetAddrInvalid:
            negative0x02_.fetch_add(1, std::memory_order_relaxed);
            break;
        case FailureCode::IntegrityFailure:
            negative0x04_.fetch_add(1, std::memory_order_relaxed);
            break;
        case FailureCode::LengthMismatch:
            negative0x08_.fetch_add(1, std::memory_order_relaxed);
            break;
        default:
            break;
    }
}

void ServerMetrics::onClientConnected() noexcept {
    activeConnections_.fetch_add(1, std::memory_order_relaxed);
    totalConnections_.fetch_add(1, std::memory_order_relaxed);
}

void ServerMetrics::onClientDisconnected() noexcept {
    if (activeConnections_.load(std::memory_order_relaxed) > 0) {
        activeConnections_.fetch_sub(1, std::memory_order_relaxed);
    }
}

uint64_t ServerMetrics::totalRequests() const noexcept {
    return totalRequests_.load(std::memory_order_relaxed);
}

uint64_t ServerMetrics::positiveResponses() const noexcept {
    return positiveResponses_.load(std::memory_order_relaxed);
}

uint64_t ServerMetrics::negativeCount(FailureCode code) const noexcept {
    switch (code) {
        case FailureCode::SourceAddrInvalid:
            return negative0x01_.load(std::memory_order_relaxed);
        case FailureCode::TargetAddrInvalid:
            return negative0x02_.load(std::memory_order_relaxed);
        case FailureCode::IntegrityFailure:
            return negative0x04_.load(std::memory_order_relaxed);
        case FailureCode::LengthMismatch:
            return negative0x08_.load(std::memory_order_relaxed);
        default:
            return 0;
    }
}

uint32_t ServerMetrics::activeConnections() const noexcept {
    return activeConnections_.load(std::memory_order_relaxed);
}

uint64_t ServerMetrics::totalConnections() const noexcept {
    return totalConnections_.load(std::memory_order_relaxed);
}

void ServerMetrics::reset() noexcept {
    totalRequests_.store(0, std::memory_order_relaxed);
    positiveResponses_.store(0, std::memory_order_relaxed);
    negative0x01_.store(0, std::memory_order_relaxed);
    negative0x02_.store(0, std::memory_order_relaxed);
    negative0x04_.store(0, std::memory_order_relaxed);
    negative0x08_.store(0, std::memory_order_relaxed);
    activeConnections_.store(0, std::memory_order_relaxed);
    totalConnections_.store(0, std::memory_order_relaxed);
}

void ServerMetrics::dump() const {
    std::ostringstream ss;
    ss << "\n--- Server Metrics Dump ---\n"
       << "  Total Connections:    " << totalConnections() << "\n"
       << "  Active Connections:   " << activeConnections() << "\n"
       << "  Total Requests:       " << totalRequests() << "\n"
       << "  Positive Responses:   " << positiveResponses() << "\n"
       << "  Negative (0x01 SA):   " << negativeCount(FailureCode::SourceAddrInvalid) << "\n"
       << "  Negative (0x02 TA):   " << negativeCount(FailureCode::TargetAddrInvalid) << "\n"
       << "  Negative (0x04 CRC):  " << negativeCount(FailureCode::IntegrityFailure) << "\n"
       << "  Negative (0x08 Len):  " << negativeCount(FailureCode::LengthMismatch) << "\n"
       << "---------------------------";
    Logger::instance().log(LogLevel::INFO, "METRICS", ss.str());
}

} // namespace gw
