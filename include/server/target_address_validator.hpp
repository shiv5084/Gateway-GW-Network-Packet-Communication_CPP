#ifndef GW_TARGET_ADDRESS_VALIDATOR_HPP
#define GW_TARGET_ADDRESS_VALIDATOR_HPP

#include "base_validator.hpp"

namespace gw {

/**
 * @brief Validator ensuring the Packet target address is valid.
 *
 * Valid target addresses: 0x3108 (Primary GW) or 0x1380 (Secondary GW).
 * Code: 0x02 (TargetAddrInvalid).
 * Precedence: Evaluated 3rd in the validation chain.
 *
 * Rule of Zero: inherits BaseValidator with no added resources.
 */
class TargetAddressValidator : public BaseValidator {
protected:
    FailureCode doValidate(const Packet& packet) const override;
};

} // namespace gw

#endif // GW_TARGET_ADDRESS_VALIDATOR_HPP
