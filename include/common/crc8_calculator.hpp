#ifndef GW_CRC8_CALCULATOR_HPP
#define GW_CRC8_CALCULATOR_HPP

#include <cstdint>
#include <cstddef>
#include <vector>
#include "gw_config.hpp"

namespace gw {

/**
 * @brief Computes CRC-8 checksums for payload integrity.
 *
 * Implements standard bit-by-bit CRC-8 with configurable polynomial
 * (default: 0x07, x^8 + x^2 + x + 1) and initial value (default: 0x00).
 *
 * Design Principles:
 * - Single Responsibility Principle (SRP): only computes CRC-8 checksums.
 * - Command-Query Separation (CQS): compute() methods are pure query functions with no side effects.
 * - Rule of Zero: manages only const scalar members; default copy, move, and destructor.
 */
class Crc8Calculator {
public:
    /**
     * @brief Construct CRC-8 calculator with given polynomial and initial value.
     * @param polynomial CRC-8 polynomial (default: GW_CRC8_POLY = 0x07).
     * @param initialValue Initial CRC register value (default: GW_CRC8_INIT = 0x00).
     */
    explicit Crc8Calculator(uint8_t polynomial = GW_CRC8_POLY,
                            uint8_t initialValue = GW_CRC8_INIT) noexcept;

    /**
     * @brief Compute CRC-8 checksum over raw byte buffer.
     * @param data Pointer to buffer.
     * @param length Number of bytes.
     * @return Computed 8-bit CRC value.
     */
    uint8_t compute(const uint8_t* data, size_t length) const noexcept;

    /**
     * @brief Compute CRC-8 checksum over std::vector<uint8_t>.
     * @param data Byte vector.
     * @return Computed 8-bit CRC value.
     */
    uint8_t compute(const std::vector<uint8_t>& data) const noexcept;

    /**
     * @brief Get configured polynomial.
     */
    uint8_t getPolynomial() const noexcept { return polynomial_; }

    /**
     * @brief Get configured initial value.
     */
    uint8_t getInitialValue() const noexcept { return initialValue_; }

private:
    uint8_t polynomial_;
    uint8_t initialValue_;
};

} // namespace gw

#endif // GW_CRC8_CALCULATOR_HPP
