#include "stream_framer.hpp"
#include "gw_config.hpp"
#include <stdexcept>

namespace gw {

ssize_t StreamFramer::recvExact(ISocket& socket, uint8_t* buffer, size_t count) {
    if (buffer == nullptr && count > 0) {
        return -1;
    }
    size_t totalReceived = 0;
    while (totalReceived < count) {
        ssize_t bytesRead = socket.recv(buffer + totalReceived, count - totalReceived);
        if (bytesRead <= 0) {
            if (totalReceived == 0) {
                return bytesRead; // 0 for orderly shutdown, <0 for error
            }
            return -1; // Abrupt disconnect during expected message body
        }
        totalReceived += static_cast<size_t>(bytesRead);
    }
    return static_cast<ssize_t>(totalReceived);
}

std::vector<uint8_t> StreamFramer::readFrame(ISocket& socket) {
    uint8_t header[GW_HEADER_SIZE];
    ssize_t headerBytes = recvExact(socket, header, GW_HEADER_SIZE);

    if (headerBytes == 0) {
        // Orderly disconnect before any header byte
        return std::vector<uint8_t>{};
    }
    if (headerBytes < 0 || static_cast<size_t>(headerBytes) != GW_HEADER_SIZE) {
        throw std::runtime_error("Failed to read header from socket");
    }

    uint32_t length = (static_cast<uint32_t>(header[4]) << 24) |
                      (static_cast<uint32_t>(header[5]) << 16) |
                      (static_cast<uint32_t>(header[6]) << 8)  |
                      static_cast<uint32_t>(header[7]);

    if (length > GW_MAX_PAYLOAD_SIZE + 1) {
        throw std::runtime_error("Frame length exceeds maximum allowed");
    }

    std::vector<uint8_t> frame(GW_HEADER_SIZE + length);
    for (size_t i = 0; i < GW_HEADER_SIZE; ++i) {
        frame[i] = header[i];
    }

    if (length > 0) {
        ssize_t bodyBytes = recvExact(socket, frame.data() + GW_HEADER_SIZE, length);
        if (bodyBytes < 0 || static_cast<size_t>(bodyBytes) != length) {
            throw std::runtime_error("Failed to read complete frame body from socket");
        }
    }

    return frame;
}

} // namespace gw
