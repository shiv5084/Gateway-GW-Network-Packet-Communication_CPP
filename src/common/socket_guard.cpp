#include "socket_guard.hpp"

namespace gw {

SocketGuard::SocketGuard() noexcept
    : handle_(GW_INVALID_SOCKET) {
}

SocketGuard::SocketGuard(gw_socket_t handle) noexcept
    : handle_(handle) {
}

SocketGuard::~SocketGuard() {
    reset();
}

SocketGuard::SocketGuard(SocketGuard&& other) noexcept
    : handle_(other.handle_) {
    other.handle_ = GW_INVALID_SOCKET;
}

SocketGuard& SocketGuard::operator=(SocketGuard&& other) noexcept {
    if (this != &other) {
        reset();
        handle_ = other.handle_;
        other.handle_ = GW_INVALID_SOCKET;
    }
    return *this;
}

gw_socket_t SocketGuard::get() const noexcept {
    return handle_;
}

gw_socket_t SocketGuard::release() noexcept {
    gw_socket_t released = handle_;
    handle_ = GW_INVALID_SOCKET;
    return released;
}

void SocketGuard::reset(gw_socket_t newHandle) noexcept {
    if (handle_ != GW_INVALID_SOCKET) {
        PlatformSocket::closeRawSocket(handle_);
    }
    handle_ = newHandle;
}

bool SocketGuard::isValid() const noexcept {
    return handle_ != GW_INVALID_SOCKET;
}

SocketGuard::operator bool() const noexcept {
    return isValid();
}

} // namespace gw
