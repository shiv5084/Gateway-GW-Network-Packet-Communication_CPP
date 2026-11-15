#ifndef GW_TCP_CLIENT_HPP
#define GW_TCP_CLIENT_HPP

#include "i_socket.hpp"
#include <string>
#include <vector>
#include <memory>
#include <cstdint>

namespace gw {

/**
 * @brief TCP client socket managing connection, sending, and receiving frames.
 *
 * Follows Rule of Five (move-only):
 * - Destructor disconnects socket.
 * - Copy operations deleted; move operations transfer socket ownership.
 */
class TcpClient {
public:
    TcpClient();
    ~TcpClient();

    // Rule of Five: move-only semantics
    TcpClient(const TcpClient&) = delete;
    TcpClient& operator=(const TcpClient&) = delete;
    TcpClient(TcpClient&& other) noexcept;
    TcpClient& operator=(TcpClient&& other) noexcept;

    void connect(const std::string& ip, uint16_t port);
    void sendFrame(const std::vector<uint8_t>& frame);
    std::vector<uint8_t> receiveFrame();
    void disconnect();

    bool isConnected() const noexcept;
    const std::string& getPeerIp() const noexcept { return peerIp_; }
    uint16_t getPeerPort() const noexcept { return peerPort_; }

private:
    std::unique_ptr<ISocket> socket_;
    std::string peerIp_;
    uint16_t peerPort_{0};
};

} // namespace gw

#endif // GW_TCP_CLIENT_HPP
