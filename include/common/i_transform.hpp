#ifndef GW_I_TRANSFORM_HPP
#define GW_I_TRANSFORM_HPP

#include <cstdint>
#include <cstddef>
#include <vector>

namespace gw {

/**
 * @brief Strategy interface for byte payload transformations.
 *
 * Implements Strategy pattern for interchangeable data transformation stages.
 * Follows Rule of Zero for interfaces.
 */
class ITransform {
public:
    virtual ~ITransform() = default;

    /**
     * @brief Apply transformation to byte buffer in-place.
     * @param data Pointer to buffer.
     * @param length Number of bytes in buffer.
     *
     * Command: mutates buffer in-place, returns void (CQS).
     */
    virtual void apply(uint8_t* data, size_t length) const = 0;
};

} // namespace gw

#endif // GW_I_TRANSFORM_HPP
