#ifndef GW_I_VALIDATION_HANDLER_HPP
#define GW_I_VALIDATION_HANDLER_HPP

#include "packet.hpp"
#include "gw_types.hpp"

namespace gw {

/**
 * @brief Abstract interface for Chain of Responsibility validation handlers.
 *
 * Each validator in the chain performs its specific validation check.
 * If valid, it delegates to the successor handler; otherwise, it short-circuits
 * and immediately returns the specific FailureCode.
 */
class IValidationHandler {
public:
    virtual ~IValidationHandler() = default;

    virtual IValidationHandler* setNext(IValidationHandler* handler) = 0;
    virtual FailureCode validate(const Packet& packet) const = 0;
};

} // namespace gw

#endif // GW_I_VALIDATION_HANDLER_HPP
