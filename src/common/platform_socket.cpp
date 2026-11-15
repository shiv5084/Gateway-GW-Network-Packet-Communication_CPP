#include "platform_socket.hpp"
#include <utility>

namespace gw {

bool PlatformSocket::initializePlatform() {
#if defined(_WIN32)
    WSADATA wsaData;
    int result = WSAStartup(MAKEWORD(2, 2), &wsaData);
    return (result == 0);
#else
    return true;
#endif
}

void PlatformSocket::cleanupPlatform() {
#if defined(_WIN32)
    WSACleanup();
#endif
}

void PlatformSocket::closeRawSocket(gw_socket_t handle) noexcept {
    if (handle != GW_INVALID_SOCKET) {
#if defined(_WIN32)
        closesocket(handle);
#else
        ::close(handle);
#endif
    }
}

PlatformSocket::PlatformSocket(gw_socket_t handle) noexcept
    : handle_(handle) {
}

PlatformSocket::~PlatformSocket() {
    close();
}

PlatformSocket::PlatformSocket(PlatformSocket&& other) noexcept
    : handle_(other.handle_) {
    other.handle_ = GW_INVALID_SOCKET;
}

PlatformSocket& PlatformSocket::operator=(PlatformSocket&& other) noexcept {
    if (this != &other) {
        close();
        handle_ = other.handle_;
        other.handle_ = GW_INVALID_SOCKET;
    }
    return *this;
}

int PlatformSocket::send(const uint8_t* data, size_t length) {
    if (handle_ == GW_INVALID_SOCKET || data == nullptr || length == 0) {
        return -1;
    }
#if defined(_WIN32)
    return ::send(handle_, reinterpret_cast<const char*>(data), static_cast<int>(length), 0);
#else
    return static_cast<int>(::send(handle_, data, length, 0));
#endif
}

ssize_t PlatformSocket::recv(uint8_t* buffer, size_t length) {
    if (handle_ == GW_INVALID_SOCKET || buffer == nullptr || length == 0) {
        return -1;
    }
#if defined(_WIN32)
    int res = ::recv(handle_, reinterpret_cast<char*>(buffer), static_cast<int>(length), 0);
    return static_cast<ssize_t>(res);
#else
    return ::recv(handle_, buffer, length, 0);
#endif
}

void PlatformSocket::close() {
    if (handle_ != GW_INVALID_SOCKET) {
        closeRawSocket(handle_);
        handle_ = GW_INVALID_SOCKET;
    }
}

bool PlatformSocket::isValid() const noexcept {
    return handle_ != GW_INVALID_SOCKET;
}

gw_socket_t PlatformSocket::getHandle() const noexcept {
    return handle_;
}

gw_socket_t PlatformSocket::release() noexcept {
    gw_socket_t temp = handle_;
    handle_ = GW_INVALID_SOCKET;
    return temp;
}

void PlatformSocket::reset(gw_socket_t newHandle) noexcept {
    if (handle_ != newHandle) {
        close();
        handle_ = newHandle;
    }
}

} // namespace gw
