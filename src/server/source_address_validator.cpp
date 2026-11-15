#include "source_address_validator.hpp"
#include "gw_types.hpp"

namespace gw {

FailureCode SourceAddressValidator::doValidate(const Packet& packet) const {
    if (!isValidSourceAddress(packet.sourceAddr())) {
        return FailureCode::SourceAddrInvalid;
    }
    return FailureCode::None;
}

} // namespace gw
