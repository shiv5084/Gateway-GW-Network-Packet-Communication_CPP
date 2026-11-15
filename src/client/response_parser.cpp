#include "response_parser.hpp"
#include "packet_parser.hpp"
#include <stdexcept>

namespace gw {

namespace {

bool isFailureCodeByte(uint8_t byte) noexcept {
    return byte == static_cast<uint8_t>(FailureCode::SourceAddrInvalid) ||
           byte == static_cast<uint8_t>(FailureCode::TargetAddrInvalid) ||
           byte == static_cast<uint8_t>(FailureCode::IntegrityFailure) ||
           byte == static_cast<uint8_t>(FailureCode::LengthMismatch);
}

} // namespace

ClientResponse ResponseParser::parse(const std::vector<uint8_t>& frameData) const {
    Packet packet = PacketParser::parse(frameData);

    uint8_t computedCrc = crcCalculator_.compute(packet.payload().data(), packet.payload().size());
    if (computedCrc != packet.crc()) {
        throw std::runtime_error("Response CRC-8 integrity check failed");
    }

    ClientResponse response;
    response.sourceAddr = packet.sourceAddr();
    response.targetAddr = packet.targetAddr();

    if (packet.payload().size() == 1 && isFailureCodeByte(packet.payload()[0])) {
        response.type = ResponseType::Negative;
        response.failureCode = static_cast<FailureCode>(packet.payload()[0]);
        response.decryptedPayload.clear();
    } else {
        response.type = ResponseType::Positive;
        response.failureCode = FailureCode::None;
        response.decryptedPayload = packet.payload();
        if (!response.decryptedPayload.empty()) {
            responseCrypto_.process(response.decryptedPayload.data(), response.decryptedPayload.size());
        }
    }

    return response;
}

} // namespace gw
