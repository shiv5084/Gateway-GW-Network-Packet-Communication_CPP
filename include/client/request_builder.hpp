#ifndef GW_REQUEST_BUILDER_HPP
#define GW_REQUEST_BUILDER_HPP

#include "i_crypto_strategy.hpp"
#include "crc8_calculator.hpp"
#include <vector>
#include <cstdint>

namespace gw {

/**
 * @brief Client-side builder to assemble valid and intentionally malformed request frames.
 *
 * Encrypts raw payload using requestCrypto (0xAA), computes CRC-8 over encrypted payload,
 * and serializes the complete big-endian frame.
 *
 * Adheres to Rule of Zero: stores non-owning references.
 */
class RequestBuilder {
public:
    RequestBuilder(const ICryptoStrategy& requestCrypto,
                   const Crc8Calculator& crcCalculator) noexcept
        : requestCrypto_(requestCrypto)
        , crcCalculator_(crcCalculator) {}

    std::vector<uint8_t> build(uint16_t sourceAddr,
                               uint16_t targetAddr,
                               const std::vector<uint8_t>& rawPayload) const;

    std::vector<uint8_t> buildInvalid(uint16_t sourceAddr,
                                      uint16_t targetAddr,
                                      const std::vector<uint8_t>& rawPayload,
                                      bool corruptCrc,
                                      bool corruptLength) const;

private:
    const ICryptoStrategy& requestCrypto_;
    const Crc8Calculator& crcCalculator_;
};

} // namespace gw

#endif // GW_REQUEST_BUILDER_HPP
