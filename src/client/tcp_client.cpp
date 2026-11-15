#include "tcp_client.hpp"
#include "platform_socket.hpp"
#include "stream_framer.hpp"
#include "logger.hpp"
#include <stdexcept>
#include <utility>

namespace gw {

TcpClient::TcpClient() = default;

TcpClient::~TcpClient() {
    disconnect();
}

TcpClient::TcpClient(TcpClient&& other) noexcept
    : socket_(std::move(other.socket_))
    , peerIp_(std::move(other.peerIp_))
    , peerPort_(other.peerPort_) {
    other.peerPort_ = 0;
}

TcpClient& TcpClient::operator=(TcpClient&& other) noexcept {
    if (this != &other) {
        disconnect();
        socket_ = std::move(other.socket_);
        peerIp_ = std::move(other.peerIp_);
        peerPort_ = other.peerPort_;
        other.peerPort_ = 0;
    }
    return *this;
}

void TcpClient::connect(const std::string& ip, uint16_t port) {
    disconnect();
    PlatformSocket::initializePlatform();

    gw_socket_t handle = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (handle == GW_INVALID_SOCKET) {
        throw std::runtime_error("Failed to create client socket");
    }

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
#if defined(_WIN32)
    addr.sin_addr.s_addr = inet_addr(ip.c_str());
#else
    inet_pton(AF_INET, ip.c_str(), &addr.sin_addr);
#endif

    if (::connect(handle, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) == GW_SOCKET_ERROR) {
        PlatformSocket::closeRawSocket(handle);
        throw std::runtime_error("Failed to connect to " + ip + ":" + std::to_string(port));
    }

    socket_.reset(new PlatformSocket(handle));
    peerIp_ = ip;
    peerPort_ = port;
    Logger::instance().log(LogLevel::INFO, "CLIENT", "Connected to " + ip + ":" + std::to_string(port));
}

void TcpClient::sendFrame(const std::vector<uint8_t>& frame) {
    if (!socket_ || !socket_->isValid()) {
        throw std::runtime_error("Socket is not connected");
    }

    Logger::instance().hexDump(LogLevel::DEBUG, "CLIENT", "TX", frame.data(), frame.size());

    int sent = socket_->send(frame.data(), frame.size());
    if (sent < 0 || static_cast<size_t>(sent) != frame.size()) {
        throw std::runtime_error("Failed to send complete frame to server");
    }
}

std::vector<uint8_t> TcpClient::receiveFrame() {
    if (!socket_ || !socket_->isValid()) {
        throw std::runtime_error("Socket is not connected");
    }
    std::vector<uint8_t> frame = StreamFramer::readFrame(*socket_);
    if (!frame.empty()) {
        Logger::instance().hexDump(LogLevel::DEBUG, "CLIENT", "RX", frame.data(), frame.size());
    }
    return frame;
}

void TcpClient::disconnect() {
    if (socket_) {
        Logger::instance().log(LogLevel::INFO, "CLIENT", "Disconnected from server");
        socket_->close();
        socket_.reset();
    }
    peerIp_.clear();
    peerPort_ = 0;
}

bool TcpClient::isConnected() const noexcept {
    return socket_ && socket_->isValid();
}

} // namespace gw
