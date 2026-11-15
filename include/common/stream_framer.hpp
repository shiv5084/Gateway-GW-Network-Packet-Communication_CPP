#ifndef GW_STREAM_FRAMER_HPP
#define GW_STREAM_FRAMER_HPP

#include "i_socket.hpp"
#include <vector>
#include <cstdint>
#include <cstddef>

namespace gw {

/**
 * @brief Static framing utility for stream-oriented TCP sockets.
 *
 * Implements two-phase framing: reads fixed 8-byte header, extracts Length,
 * then reads exactly Length more bytes into a complete frame buffer.
 *
 * Adheres to Rule of Zero: pure static utility class, no instance state.
 */
class StreamFramer {
public:
    static ssize_t recvExact(ISocket& socket, uint8_t* buffer, size_t count);
    static std::vector<uint8_t> readFrame(ISocket& socket);
};

} // namespace gw

#endif // GW_STREAM_FRAMER_HPP
