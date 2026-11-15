#include "xor_crypto_strategy.hpp"

namespace gw {

XorCryptoStrategy::XorCryptoStrategy(uint8_t key) noexcept
    : key_(key) {
}

void XorCryptoStrategy::process(uint8_t* data, size_t length) const {
    if (data == nullptr || length == 0) {
        return;
    }

    for (size_t i = 0; i < length; ++i) {
        data[i] ^= key_;
    }
}

void XorCryptoStrategy::process(std::vector<uint8_t>& data) const {
    process(data.data(), data.size());
}

uint8_t XorCryptoStrategy::getKey() const noexcept {
    return key_;
}

} // namespace gw
