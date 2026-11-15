#include "crc_validator.hpp"

namespace gw {

FailureCode CrcValidator::doValidate(const Packet& packet) const {
    uint8_t computed = crcCalculator_.compute(packet.payload().data(), packet.payload().size());
    if (computed != packet.crc()) {
        return FailureCode::IntegrityFailure;
    }
    return FailureCode::None;
}

} // namespace gw
