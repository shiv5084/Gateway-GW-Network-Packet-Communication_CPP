#include "length_validator.hpp"

namespace gw {

FailureCode LengthValidator::doValidate(const Packet& packet) const {
    if (packet.length() < 2 || packet.length() != packet.payload().size() + 1) {
        return FailureCode::LengthMismatch;
    }
    return FailureCode::None;
}

} // namespace gw
