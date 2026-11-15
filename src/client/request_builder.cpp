#include "request_builder.hpp"
#include "packet.hpp"
#include "gw_config.hpp"

namespace gw {

std::vector<uint8_t> RequestBuilder::build(uint16_t sourceAddr,
                                           uint16_t targetAddr,
                                           const std::vector<uint8_t>& rawPayload) const {
    std::vector<uint8_t> encrypted = rawPayload;
    if (!encrypted.empty()) {
        requestCrypto_.process(encrypted.data(), encrypted.size());
    }

    uint8_t crc = crcCalculator_.compute(encrypted.data(), encrypted.size());
    uint32_t length = static_cast<uint32_t>(encrypted.size() + GW_CRC_SIZE);

    Packet packet(sourceAddr, targetAddr, length, std::move(encrypted), crc);
    return packet.serialize();
}

std::vector<uint8_t> RequestBuilder::buildInvalid(uint16_t sourceAddr,
                                                 uint16_t targetAddr,
                                                 const std::vector<uint8_t>& rawPayload,
                                                 bool corruptCrc,
                                                 bool corruptLength) const {
    std::vector<uint8_t> encrypted = rawPayload;
    if (!encrypted.empty()) {
        requestCrypto_.process(encrypted.data(), encrypted.size());
    }

    uint8_t crc = crcCalculator_.compute(encrypted.data(), encrypted.size());
    if (corruptCrc) {
        crc ^= 0xFF;
    }

    uint32_t length = static_cast<uint32_t>(encrypted.size() + GW_CRC_SIZE);
    if (corruptLength) {
        length += 10;
    }

    Packet packet(sourceAddr, targetAddr, length, std::move(encrypted), crc);
    return packet.serialize();
}

} // namespace gw
