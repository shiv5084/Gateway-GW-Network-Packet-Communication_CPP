#ifndef GW_I_CRYPTO_STRATEGY_HPP
#define GW_I_CRYPTO_STRATEGY_HPP

#include <cstdint>
#include <cstddef>
#include <vector>

namespace gw {

/**
 * @brief Strategy interface for pluggable cryptographic operations.
 *
 * Implements Strategy pattern (GoF Behavioral).
 * Follows Rule of Zero for interfaces (virtual destructor for polymorphic deletion,
 * no resource ownership in interface).
 */
class ICryptoStrategy {
public:
    virtual ~ICryptoStrategy() = default;

    /**
     * @brief Process (encrypt or decrypt) buffer in-place.
     * @param data Pointer to byte buffer to be transformed in-place.
     * @param length Number of bytes in buffer.
     *
     * Command: mutates the buffer in-place, returns void (CQS).
     */
    virtual void process(uint8_t* data, size_t length) const = 0;

    /**
     * @brief Get the cryptographic key associated with this strategy.
     *
     * Query: pure accessor with no side effects (CQS).
     */
    virtual uint8_t getKey() const noexcept = 0;
};

} // namespace gw

#endif // GW_I_CRYPTO_STRATEGY_HPP
