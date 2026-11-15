#include "base_validator.hpp"

namespace gw {

IValidationHandler* BaseValidator::setNext(IValidationHandler* handler) {
    next_ = handler;
    return handler;
}

FailureCode BaseValidator::validate(const Packet& packet) const {
    FailureCode code = doValidate(packet);
    if (code != FailureCode::None) {
        return code;
    }
    if (next_ != nullptr) {
        return next_->validate(packet);
    }
    return FailureCode::None;
}

} // namespace gw
