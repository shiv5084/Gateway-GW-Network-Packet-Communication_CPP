#ifndef GW_XOR_CRYPTO_STRATEGY_HPP
#define GW_XOR_CRYPTO_STRATEGY_HPP

#include "i_crypto_strategy.hpp"

namespace gw {

/**
 * @brief Concrete strategy implementing symmetric XOR byte encryption/decryption.
 *
 * Symmetrical: applying the same strategy twice restores original data.
 *
 * Design Principles:
 * - Strategy Pattern: concrete algorithm implementing ICryptoStrategy.
 * - Single Responsibility Principle (SRP): only performs XOR transformation.
 * - Rule of Zero: only const scalar member (key_); compiler-generated copy/move/dtor.
 * - Command-Query Separation (CQS): process() is a Command, getKey() is a Query.
 */
class XorCryptoStrategy : public ICryptoStrategy {
public:
    /**
     * @brief Construct XOR strategy with specific 1-byte key.
     * @param key XOR encryption/decryption key.
     */
    explicit XorCryptoStrategy(uint8_t key) noexcept;

    /**
     * @brief Encrypt or decrypt buffer in-place using XOR key.
     */
    void process(uint8_t* data, size_t length) const override;

    /**
     * @brief Convenience overload for vector buffer.
     */
    void process(std::vector<uint8_t>& data) const;

    /**
     * @brief Access the configured XOR key.
     */
    uint8_t getKey() const noexcept override;

private:
    uint8_t key_;
};

} // namespace gw

#endif // GW_XOR_CRYPTO_STRATEGY_HPP
