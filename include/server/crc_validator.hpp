#ifndef GW_CRC_VALIDATOR_HPP
#define GW_CRC_VALIDATOR_HPP

#include "base_validator.hpp"
#include "crc8_calculator.hpp"

namespace gw {

/**
 * @brief Validator ensuring the Packet CRC matches the computed CRC-8 over payload.
 *
 * Code: 0x04 (IntegrityFailure).
 * Precedence: Evaluated 4th in the validation chain.
 *
 * Rule of Zero: holds non-owning const Crc8Calculator& via dependency injection.
 */
class CrcValidator : public BaseValidator {
public:
    explicit CrcValidator(const Crc8Calculator& crcCalculator) noexcept
        : crcCalculator_(crcCalculator) {}

protected:
    FailureCode doValidate(const Packet& packet) const override;

private:
    const Crc8Calculator& crcCalculator_;
};

} // namespace gw

#endif // GW_CRC_VALIDATOR_HPP
