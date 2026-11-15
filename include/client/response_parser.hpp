#ifndef GW_RESPONSE_PARSER_HPP
#define GW_RESPONSE_PARSER_HPP

#include "gw_types.hpp"
#include "i_crypto_strategy.hpp"
#include "crc8_calculator.hpp"
#include <vector>
#include <cstdint>

namespace gw {

/**
 * @brief Decoded response representation for clients.
 *
 * Adheres to Rule of Zero: std::vector self-manages payload memory.
 */
struct ClientResponse {
    ResponseType type{ResponseType::Positive};
    uint16_t sourceAddr{0};
    uint16_t targetAddr{0};
    FailureCode failureCode{FailureCode::None};
    std::vector<uint8_t> decryptedPayload;
};

/**
 * @brief Client-side response decoder.
 *
 * Validates frame structure and CRC-8 integrity.
 * Differentiates positive and negative responses.
 * Decrypts payload for positive responses using responseCrypto (0x55).
 * Extracts unencrypted FailureCode for negative responses.
 *
 * Adheres to Rule of Zero: stores non-owning references.
 */
class ResponseParser {
public:
    ResponseParser(const ICryptoStrategy& responseCrypto,
                   const Crc8Calculator& crcCalculator) noexcept
        : responseCrypto_(responseCrypto)
        , crcCalculator_(crcCalculator) {}

    ClientResponse parse(const std::vector<uint8_t>& frameData) const;

private:
    const ICryptoStrategy& responseCrypto_;
    const Crc8Calculator& crcCalculator_;
};

} // namespace gw

#endif // GW_RESPONSE_PARSER_HPP
