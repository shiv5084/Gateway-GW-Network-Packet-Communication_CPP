#ifndef GW_PACKET_HPP
#define GW_PACKET_HPP

#include <cstdint>
#include <vector>

namespace gw {

/**
 * @brief Immutable value object representing a protocol packet.
 *
 * Encapsulates the 8-byte big-endian header (Source Address, Target Address, Length),
 * the payload bytes, and the 1-byte CRC.
 *
 * Adheres to the Rule of Zero: std::vector manages payload memory;
 * compiler-generated copy/move/destruction semantics are optimal.
 */
class Packet {
public:
    Packet(uint16_t sourceAddr,
           uint16_t targetAddr,
           uint32_t length,
           std::vector<uint8_t> payload,
           uint8_t crc);

    uint16_t sourceAddr() const noexcept { return sourceAddr_; }
    uint16_t targetAddr() const noexcept { return targetAddr_; }
    uint32_t length() const noexcept { return length_; }
    uint32_t payloadLen() const noexcept { return length_ > 0 ? length_ - 1 : 0; }
    const std::vector<uint8_t>& payload() const noexcept { return payload_; }
    uint8_t crc() const noexcept { return crc_; }

    std::vector<uint8_t> serialize() const;
    bool equals(const Packet& other) const noexcept;

private:
    uint16_t sourceAddr_{0};
    uint16_t targetAddr_{0};
    uint32_t length_{0};
    std::vector<uint8_t> payload_;
    uint8_t crc_{0};
};

} // namespace gw

#endif // GW_PACKET_HPP
