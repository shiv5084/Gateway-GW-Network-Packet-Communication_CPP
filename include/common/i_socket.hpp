#ifndef GW_I_SOCKET_HPP
#define GW_I_SOCKET_HPP

#include <cstdint>
#include <cstddef>
#if defined(_MSC_VER)
#include <BaseTsd.h>
typedef SSIZE_T ssize_t;
#else
#include <sys/types.h>
#endif

namespace gw {

/**
 * @brief Abstract interface for network socket abstraction.
 *
 * Rule of Zero: interface defines virtual destructor for polymorphic deletion,
 * with no resource ownership in the interface itself.
 */
class ISocket {
public:
    virtual ~ISocket() = default;

    /**
     * @brief Send data through the socket.
     * @param data Pointer to byte buffer to transmit.
     * @param length Number of bytes to send.
     * @return Number of bytes actually sent, or negative on error.
     */
    virtual int send(const uint8_t* data, size_t length) = 0;

    /**
     * @brief Receive data from the socket.
     * @param buffer Destination buffer for received bytes.
     * @param length Maximum number of bytes to receive.
     * @return Number of bytes read (0 on orderly disconnect, negative on error).
     */
    virtual ssize_t recv(uint8_t* buffer, size_t length) = 0;

    /**
     * @brief Close the underlying socket handle.
     */
    virtual void close() = 0;

    /**
     * @brief Check if the socket handle is valid and open.
     */
    virtual bool isValid() const noexcept = 0;
};

} // namespace gw

#endif // GW_I_SOCKET_HPP
