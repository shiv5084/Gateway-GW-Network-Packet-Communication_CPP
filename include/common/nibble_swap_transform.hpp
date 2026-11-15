#ifndef GW_NIBBLE_SWAP_TRANSFORM_HPP
#define GW_NIBBLE_SWAP_TRANSFORM_HPP

#include "i_transform.hpp"

namespace gw {

/**
 * @brief Swaps the high and low 4-bit nibbles of each byte in the payload.
 *
 * For each byte: Transformed_Byte[i] = ((Payload[i] & 0x0F) << 4) | ((Payload[i] & 0xF0) >> 4)
 * Example: 0x12 -> 0x21, 0xAB -> 0xBA
 * Symmetrical: applying twice restores the original data.
 *
 * Design Principles:
 * - Single Responsibility Principle (SRP): only performs nibble swapping.
 * - Command-Query Separation (CQS): apply() is a Command mutating the buffer in-place.
 * - Rule of Zero: stateless class, no data members.
 */
class NibbleSwapTransform : public ITransform {
public:
    NibbleSwapTransform() noexcept = default;

    /**
     * @brief Apply nibble swap to buffer in-place.
     */
    void apply(uint8_t* data, size_t length) const override;

    /**
     * @brief Convenience overload for vector buffer.
     */
    void apply(std::vector<uint8_t>& data) const;
};

} // namespace gw

#endif // GW_NIBBLE_SWAP_TRANSFORM_HPP
