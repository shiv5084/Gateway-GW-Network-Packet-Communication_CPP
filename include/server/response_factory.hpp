#ifndef GW_RESPONSE_FACTORY_HPP
#define GW_RESPONSE_FACTORY_HPP

#include "packet.hpp"
#include "gw_types.hpp"
#include "i_crypto_strategy.hpp"
#include "crc8_calculator.hpp"
#include <vector>
#include <cstdint>

namespace gw {

/**
 * @brief Factory class to assemble positive and negative response frames.
 *
 * Implements Factory Method pattern:
 * - Positive response: swaps SA/TA, encrypts payload using responseCrypto,
 *   computes CRC-8, and serializes frame.
 * - Negative response: swaps SA/TA, appends unencrypted FailureCode byte,
 *   computes CRC-8 over FailureCode, and serializes exactly 10-byte frame.
 *
 * Adheres to Rule of Zero: stores non-owning references.
 */
class ResponseFactory {
public:
    ResponseFactory(const ICryptoStrategy& responseCrypto,
                    const Crc8Calculator& crcCalculator) noexcept
        : responseCrypto_(responseCrypto)
        , crcCalculator_(crcCalculator) {}

    std::vector<uint8_t> create(const Packet& request,
                                FailureCode code,
                                const std::vector<uint8_t>& transformedPayload = {}) const;

private:
    std::vector<uint8_t> createPositive(const Packet& request,
                                        const std::vector<uint8_t>& transformedPayload) const;

    std::vector<uint8_t> createNegative(const Packet& request,
                                        FailureCode code) const;

    const ICryptoStrategy& responseCrypto_;
    const Crc8Calculator& crcCalculator_;
};

} // namespace gw

#endif // GW_RESPONSE_FACTORY_HPP
