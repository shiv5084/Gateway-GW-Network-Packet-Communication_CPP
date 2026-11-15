#ifndef GW_SERVER_METRICS_HPP
#define GW_SERVER_METRICS_HPP

#include "gw_types.hpp"
#include <atomic>
#include <cstdint>

namespace gw {

/**
 * @brief Thread-safe operational telemetry singleton for the gateway server.
 *
 * Implements Singleton and Observer patterns.
 * Follows Rule of Five: non-copyable, non-movable singleton.
 * Follows CQS: Observer methods are Commands, accessors are Queries.
 */
class ServerMetrics {
public:
    static ServerMetrics& instance();

    // Rule of Five: Singleton — delete ALL copy and move operations
    ~ServerMetrics() = default;
    ServerMetrics(const ServerMetrics&) = delete;
    ServerMetrics& operator=(const ServerMetrics&) = delete;
    ServerMetrics(ServerMetrics&&) = delete;
    ServerMetrics& operator=(ServerMetrics&&) = delete;

    // Observer notifications (Commands: modify atomic counters)
    void onRequestReceived() noexcept;
    void onPositiveResponse() noexcept;
    void onNegativeResponse(FailureCode code) noexcept;
    void onClientConnected() noexcept;
    void onClientDisconnected() noexcept;

    // Accessors (Queries: const, thread-safe reads)
    uint64_t totalRequests() const noexcept;
    uint64_t positiveResponses() const noexcept;
    uint64_t negativeCount(FailureCode code) const noexcept;
    uint32_t activeConnections() const noexcept;
    uint64_t totalConnections() const noexcept;

    // Reset all counters (for testing)
    void reset() noexcept;

    // Snapshot log dump
    void dump() const;

private:
    ServerMetrics() = default;

    std::atomic<uint64_t> totalRequests_{0};
    std::atomic<uint64_t> positiveResponses_{0};
    std::atomic<uint64_t> negative0x01_{0};
    std::atomic<uint64_t> negative0x02_{0};
    std::atomic<uint64_t> negative0x04_{0};
    std::atomic<uint64_t> negative0x08_{0};
    std::atomic<uint32_t> activeConnections_{0};
    std::atomic<uint64_t> totalConnections_{0};
};

} // namespace gw

#endif // GW_SERVER_METRICS_HPP
