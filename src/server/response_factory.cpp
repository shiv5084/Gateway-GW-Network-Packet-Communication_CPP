#include "response_factory.hpp"
#include "gw_config.hpp"

namespace gw {

std::vector<uint8_t> ResponseFactory::create(const Packet& request,
                                            FailureCode code,
                                            const std::vector<uint8_t>& transformedPayload) const {
    if (code == FailureCode::None) {
        return createPositive(request, transformedPayload);
    }
    return createNegative(request, code);
}

std::vector<uint8_t> ResponseFactory::createPositive(const Packet& request,
                                                    const std::vector<uint8_t>& transformedPayload) const {
    uint16_t respSa = request.targetAddr();
    uint16_t respTa = request.sourceAddr();

    std::vector<uint8_t> encrypted = transformedPayload;
    if (!encrypted.empty()) {
        responseCrypto_.process(encrypted.data(), encrypted.size());
    }

    uint8_t crc = crcCalculator_.compute(encrypted.data(), encrypted.size());
    uint32_t length = static_cast<uint32_t>(encrypted.size() + GW_CRC_SIZE);

    Packet respPacket(respSa, respTa, length, std::move(encrypted), crc);
    return respPacket.serialize();
}

std::vector<uint8_t> ResponseFactory::createNegative(const Packet& request,
                                                    FailureCode code) const {
    uint16_t respSa = request.targetAddr();
    uint16_t respTa = request.sourceAddr();

    uint8_t failureByte = static_cast<uint8_t>(code);
    uint8_t crc = crcCalculator_.compute(&failureByte, 1);
    uint32_t length = 2; // 1 byte code + 1 byte CRC

    Packet respPacket(respSa, respTa, length, {failureByte}, crc);
    return respPacket.serialize();
}

} // namespace gw
