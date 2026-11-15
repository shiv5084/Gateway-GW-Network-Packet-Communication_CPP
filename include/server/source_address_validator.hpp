#ifndef GW_SOURCE_ADDRESS_VALIDATOR_HPP
#define GW_SOURCE_ADDRESS_VALIDATOR_HPP

#include "base_validator.hpp"

namespace gw {

/**
 * @brief Validator ensuring the Packet source address is valid.
 *
 * Valid source addresses: 0x0E80 (Primary Node) or 0xE008 (Secondary Node).
 * Code: 0x01 (SourceAddrInvalid).
 * Precedence: Evaluated 2nd in the validation chain.
 *
 * Rule of Zero: inherits BaseValidator with no added resources.
 */
class SourceAddressValidator : public BaseValidator {
protected:
    FailureCode doValidate(const Packet& packet) const override;
};

} // namespace gw

#endif // GW_SOURCE_ADDRESS_VALIDATOR_HPP
