#include "packet_parser.hpp"
#include "gw_config.hpp"
#include <stdexcept>
#include <utility>

namespace gw {

Packet PacketParser::parse(const std::vector<uint8_t>& frameData) {
    return parse(frameData.data(), frameData.size());
}

Packet PacketParser::parse(const uint8_t* data, size_t size) {
    if (data == nullptr || size < GW_MIN_PACKET_SIZE) {
        throw std::invalid_argument("Frame size less than minimum required size");
    }

    uint16_t sourceAddr = static_cast<uint16_t>((static_cast<uint16_t>(data[0]) << 8) | data[1]);
    uint16_t targetAddr = static_cast<uint16_t>((static_cast<uint16_t>(data[2]) << 8) | data[3]);
    uint32_t length = (static_cast<uint32_t>(data[4]) << 24) |
                      (static_cast<uint32_t>(data[5]) << 16) |
                      (static_cast<uint32_t>(data[6]) << 8)  |
                      static_cast<uint32_t>(data[7]);

    if (length < 2) {
        throw std::invalid_argument("Packet length field must be at least 2 (payload + CRC)");
    }

    if (size != GW_HEADER_SIZE + length) {
        throw std::invalid_argument("Frame size does not match header length field");
    }

    size_t payloadSize = length - 1;
    std::vector<uint8_t> payload(data + GW_HEADER_SIZE, data + GW_HEADER_SIZE + payloadSize);
    uint8_t crc = data[GW_HEADER_SIZE + payloadSize];

    return Packet(sourceAddr, targetAddr, length, std::move(payload), crc);
}

} // namespace gw
