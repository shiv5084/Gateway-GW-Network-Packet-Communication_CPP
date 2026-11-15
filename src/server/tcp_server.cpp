#include "tcp_server.hpp"
#include "platform_socket.hpp"
#include "logger.hpp"
#include <stdexcept>
#include <string>

#if defined(_WIN32)
typedef int gw_socklen_t;
#else
typedef socklen_t gw_socklen_t;
#endif

namespace gw {

TcpServer::TcpServer() = default;

TcpServer::~TcpServer() {
    stop();
}

void TcpServer::bind(uint16_t port) {
    PlatformSocket::initializePlatform();

    gw_socket_t handle = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (handle == GW_INVALID_SOCKET) {
        throw std::runtime_error("Failed to create server socket");
    }

    int opt = 1;
#if defined(_WIN32)
    ::setsockopt(handle, SOL_SOCKET, SO_REUSEADDR, reinterpret_cast<const char*>(&opt), sizeof(opt));
#else
    ::setsockopt(handle, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
#endif

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(port);

    if (::bind(handle, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) == GW_SOCKET_ERROR) {
        PlatformSocket::closeRawSocket(handle);
        throw std::runtime_error("Failed to bind server socket to port " + std::to_string(port));
    }

    listenerGuard_.reset(handle);
    port_ = port;
}

void TcpServer::listen(int backlog) {
    if (!listenerGuard_.isValid()) {
        throw std::runtime_error("Cannot listen on invalid server socket");
    }

    if (::listen(listenerGuard_.get(), backlog) == GW_SOCKET_ERROR) {
        throw std::runtime_error("Failed to listen on server socket");
    }
}

void TcpServer::acceptLoop(ConnectionCallback handler) {
    if (!listenerGuard_.isValid() || !handler) {
        return;
    }

    running_.store(true, std::memory_order_relaxed);

    while (running_.load(std::memory_order_relaxed)) {
        sockaddr_in clientAddr{};
        gw_socklen_t clientLen = sizeof(clientAddr);
        gw_socket_t clientHandle = ::accept(listenerGuard_.get(),
                                           reinterpret_cast<sockaddr*>(&clientAddr),
                                           &clientLen);

        if (clientHandle == GW_INVALID_SOCKET) {
            if (!running_.load(std::memory_order_relaxed)) {
                break;
            }
            continue;
        }

        char ipStr[INET_ADDRSTRLEN] = "127.0.0.1";
        inet_ntop(AF_INET, &(clientAddr.sin_addr), ipStr, sizeof(ipStr));
        std::string peerEndpoint = std::string(ipStr) + ":" + std::to_string(ntohs(clientAddr.sin_port));

        std::lock_guard<std::mutex> lock(threadsMutex_);
        gw_socket_t handle = clientHandle;
        workerThreads_.emplace_back([handler, handle, peerEndpoint]() {
            SocketGuard guard(handle);
            handler(std::move(guard), peerEndpoint);
        });
    }
}

void TcpServer::acceptLoop(SimpleConnectionCallback handler) {
    acceptLoop([handler](SocketGuard guard, const std::string& /* peerEndpoint */) {
        handler(std::move(guard));
    });
}

void TcpServer::stop() {
    running_.store(false, std::memory_order_relaxed);
    if (listenerGuard_.isValid()) {
        listenerGuard_.reset();
    }

    std::lock_guard<std::mutex> lock(threadsMutex_);
    for (auto& th : workerThreads_) {
        if (th.joinable()) {
            th.join();
        }
    }
    workerThreads_.clear();
}

} // namespace gw
