#include "packet.hpp"
#include <utility>

namespace gw {

Packet::Packet(uint16_t sourceAddr,
               uint16_t targetAddr,
               uint32_t length,
               std::vector<uint8_t> payload,
               uint8_t crc)
    : sourceAddr_(sourceAddr)
    , targetAddr_(targetAddr)
    , length_(length)
    , payload_(std::move(payload))
    , crc_(crc) {}

std::vector<uint8_t> Packet::serialize() const {
    std::vector<uint8_t> buffer;
    buffer.reserve(8 + payload_.size() + 1);

    // Source Address (big-endian)
    buffer.push_back(static_cast<uint8_t>((sourceAddr_ >> 8) & 0xFF));
    buffer.push_back(static_cast<uint8_t>(sourceAddr_ & 0xFF));

    // Target Address (big-endian)
    buffer.push_back(static_cast<uint8_t>((targetAddr_ >> 8) & 0xFF));
    buffer.push_back(static_cast<uint8_t>(targetAddr_ & 0xFF));

    // Length (big-endian)
    buffer.push_back(static_cast<uint8_t>((length_ >> 24) & 0xFF));
    buffer.push_back(static_cast<uint8_t>((length_ >> 16) & 0xFF));
    buffer.push_back(static_cast<uint8_t>((length_ >> 8) & 0xFF));
    buffer.push_back(static_cast<uint8_t>(length_ & 0xFF));

    // Payload
    buffer.insert(buffer.end(), payload_.begin(), payload_.end());

    // CRC
    buffer.push_back(crc_);

    return buffer;
}

bool Packet::equals(const Packet& other) const noexcept {
    return sourceAddr_ == other.sourceAddr_ &&
           targetAddr_ == other.targetAddr_ &&
           length_ == other.length_ &&
           crc_ == other.crc_ &&
           payload_ == other.payload_;
}

} // namespace gw
