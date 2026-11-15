#include "crc8_calculator.hpp"

namespace gw {

Crc8Calculator::Crc8Calculator(uint8_t polynomial, uint8_t initialValue) noexcept
    : polynomial_(polynomial), initialValue_(initialValue) {
}

uint8_t Crc8Calculator::compute(const uint8_t* data, size_t length) const noexcept {
    if (data == nullptr || length == 0) {
        return initialValue_;
    }

    uint8_t crc = initialValue_;
    for (size_t i = 0; i < length; ++i) {
        crc ^= data[i];
        for (int bit = 0; bit < 8; ++bit) {
            if (crc & 0x80) {
                crc = static_cast<uint8_t>((crc << 1) ^ polynomial_);
            } else {
                crc = static_cast<uint8_t>(crc << 1);
            }
        }
    }
    return crc;
}

uint8_t Crc8Calculator::compute(const std::vector<uint8_t>& data) const noexcept {
    return compute(data.data(), data.size());
}

} // namespace gw
