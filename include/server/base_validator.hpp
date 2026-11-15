#ifndef GW_BASE_VALIDATOR_HPP
#define GW_BASE_VALIDATOR_HPP

#include "i_validation_handler.hpp"

namespace gw {

/**
 * @brief Abstract base class providing common chaining logic for validators.
 *
 * Adheres to Rule of Zero: non-owning pointer next_ requires no custom destructor,
 * copy or move operations.
 */
class BaseValidator : public IValidationHandler {
public:
    IValidationHandler* setNext(IValidationHandler* handler) override;
    FailureCode validate(const Packet& packet) const override;

protected:
    virtual FailureCode doValidate(const Packet& packet) const = 0;

private:
    IValidationHandler* next_{nullptr};
};

} // namespace gw

#endif // GW_BASE_VALIDATOR_HPP
