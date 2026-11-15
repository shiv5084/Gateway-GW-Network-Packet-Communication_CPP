#ifndef GW_TCP_SERVER_HPP
#define GW_TCP_SERVER_HPP

#include "socket_guard.hpp"
#include <cstdint>
#include <atomic>
#include <functional>
#include <vector>
#include <thread>
#include <mutex>
#include <string>

namespace gw {

/**
 * @brief Manages listener socket lifecycle and connection dispatching.
 *
 * Follows Rule of Five (non-movable):
 * - Destructor cleans up and joins threads.
 * - Copy and move operations are deleted (owns listener socket + thread list).
 */
class TcpServer {
public:
    using ConnectionCallback = std::function<void(SocketGuard, std::string)>;
    using SimpleConnectionCallback = std::function<void(SocketGuard)>;

    TcpServer();
    ~TcpServer();

    // Rule of Five: non-copyable, non-movable
    TcpServer(const TcpServer&) = delete;
    TcpServer& operator=(const TcpServer&) = delete;
    TcpServer(TcpServer&&) = delete;
    TcpServer& operator=(TcpServer&&) = delete;

    void bind(uint16_t port);
    void listen(int backlog = 32);
    void acceptLoop(ConnectionCallback handler);
    void acceptLoop(SimpleConnectionCallback handler);
    void stop();

    bool isRunning() const noexcept { return running_.load(std::memory_order_relaxed); }
    uint16_t getPort() const noexcept { return port_; }

private:
    uint16_t port_{0};
    SocketGuard listenerGuard_;
    std::atomic<bool> running_{false};
    std::vector<std::thread> workerThreads_;
    std::mutex threadsMutex_;
};

} // namespace gw

#endif // GW_TCP_SERVER_HPP
