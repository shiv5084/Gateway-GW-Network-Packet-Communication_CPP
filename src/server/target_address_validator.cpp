#include "target_address_validator.hpp"
#include "gw_types.hpp"

namespace gw {

FailureCode TargetAddressValidator::doValidate(const Packet& packet) const {
    if (!isValidTargetAddress(packet.targetAddr())) {
        return FailureCode::TargetAddrInvalid;
    }
    return FailureCode::None;
}

} // namespace gw
