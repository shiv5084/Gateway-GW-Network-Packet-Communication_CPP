#ifndef GW_SOCKET_GUARD_HPP
#define GW_SOCKET_GUARD_HPP

#include "platform_socket.hpp"

namespace gw {

/**
 * @brief RAII wrapper for low-level OS socket handles (gw_socket_t).
 *
 * Ensures automatic socket teardown on scope exit or exception.
 * Follows Rule of Five (move-only type):
 * - Copy constructor and assignment are deleted.
 * - Move constructor and assignment transfer ownership and invalidate source.
 * - Destructor closes the handle if valid.
 */
class SocketGuard {
public:
    /**
     * @brief Construct an empty SocketGuard.
     */
    SocketGuard() noexcept;

    /**
     * @brief Take ownership of a raw socket handle.
     * @param handle Raw OS socket handle.
     */
    explicit SocketGuard(gw_socket_t handle) noexcept;

    /**
     * @brief Destructor auto-closes handle if open.
     */
    ~SocketGuard();

    // Rule of Five: move-only semantics
    SocketGuard(const SocketGuard&) = delete;
    SocketGuard& operator=(const SocketGuard&) = delete;
    SocketGuard(SocketGuard&& other) noexcept;
    SocketGuard& operator=(SocketGuard&& other) noexcept;

    /**
     * @brief Get the underlying socket handle without transferring ownership.
     */
    gw_socket_t get() const noexcept;

    /**
     * @brief Relinquish ownership and return the handle.
     */
    gw_socket_t release() noexcept;

    /**
     * @brief Close current handle and take ownership of a new one.
     */
    void reset(gw_socket_t newHandle = GW_INVALID_SOCKET) noexcept;

    /**
     * @brief Check if the managed socket handle is valid.
     */
    bool isValid() const noexcept;

    /**
     * @brief Explicit boolean conversion operator.
     */
    explicit operator bool() const noexcept;

private:
    gw_socket_t handle_;
};

} // namespace gw

#endif // GW_SOCKET_GUARD_HPP
