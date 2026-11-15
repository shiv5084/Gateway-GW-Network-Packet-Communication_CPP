#ifndef GW_PLATFORM_SOCKET_HPP
#define GW_PLATFORM_SOCKET_HPP

#include "i_socket.hpp"
#include <string>

#if defined(_WIN32)
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <winsock2.h>
#include <ws2tcpip.h>
typedef SOCKET gw_socket_t;
constexpr gw_socket_t GW_INVALID_SOCKET = INVALID_SOCKET;
constexpr int GW_SOCKET_ERROR = SOCKET_ERROR;
#else
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
typedef int gw_socket_t;
constexpr gw_socket_t GW_INVALID_SOCKET = -1;
constexpr int GW_SOCKET_ERROR = -1;
#endif

namespace gw {

/**
 * @brief Platform adapter wrapping OS-specific socket operations behind ISocket.
 *
 * Implements the Adapter pattern (GoF Structural).
 * Follows Rule of Five (move-only resource manager).
 */
class PlatformSocket : public ISocket {
public:
    /**
     * @brief Initialize platform socket subsystem (WSAStartup on Windows).
     * @return true on success, false on failure.
     */
    static bool initializePlatform();

    /**
     * @brief Cleanup platform socket subsystem (WSACleanup on Windows).
     */
    static void cleanupPlatform();

    /**
     * @brief Close a raw socket handle using the platform-specific API.
     */
    static void closeRawSocket(gw_socket_t handle) noexcept;

    /**
     * @brief Construct adapter wrapping a raw socket handle.
     */
    explicit PlatformSocket(gw_socket_t handle = GW_INVALID_SOCKET) noexcept;

    /**
     * @brief Destructor closes socket if valid.
     */
    ~PlatformSocket() override;

    // Rule of Five declarations
    PlatformSocket(const PlatformSocket&) = delete;
    PlatformSocket& operator=(const PlatformSocket&) = delete;
    PlatformSocket(PlatformSocket&& other) noexcept;
    PlatformSocket& operator=(PlatformSocket&& other) noexcept;

    // ISocket interface implementation
    int send(const uint8_t* data, size_t length) override;
    ssize_t recv(uint8_t* buffer, size_t length) override;
    void close() override;
    bool isValid() const noexcept override;

    /**
     * @brief Access the underlying OS socket handle.
     */
    gw_socket_t getHandle() const noexcept;

    /**
     * @brief Release ownership of the socket handle without closing it.
     */
    gw_socket_t release() noexcept;

    /**
     * @brief Reset with a new socket handle (closing previous if valid).
     */
    void reset(gw_socket_t newHandle = GW_INVALID_SOCKET) noexcept;

private:
    gw_socket_t handle_;
};

} // namespace gw

#endif // GW_PLATFORM_SOCKET_HPP
