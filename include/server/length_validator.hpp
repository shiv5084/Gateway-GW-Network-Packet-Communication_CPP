#ifndef GW_LENGTH_VALIDATOR_HPP
#define GW_LENGTH_VALIDATOR_HPP

#include "base_validator.hpp"

namespace gw {

/**
 * @brief Validator ensuring the Packet length field is consistent with payload size.
 *
 * Code: 0x08 (LengthMismatch).
 * Precedence: Evaluated 1st in the validation chain.
 *
 * Rule of Zero: inherits BaseValidator with no added resources.
 */
class LengthValidator : public BaseValidator {
protected:
    FailureCode doValidate(const Packet& packet) const override;
};

} // namespace gw

#endif // GW_LENGTH_VALIDATOR_HPP
