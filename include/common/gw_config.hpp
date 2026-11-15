#ifndef GW_CONFIG_HPP
#define GW_CONFIG_HPP

#include <cstdint>
#include <cstddef>

namespace gw {

/**
 * @brief Gateway configuration constants.
 *
 * All values are specified by the Gateway Requirement Specification.
 */
constexpr uint16_t DEFAULT_PORT            = 13400;
constexpr size_t   GW_HEADER_SIZE          = 8;      // SA(2B) + TA(2B) + Length(4B)
constexpr size_t   GW_CRC_SIZE             = 1;      // CRC-8(1B)
constexpr size_t   GW_MIN_PACKET_SIZE      = 9;      // Header(8B) + FailureCode/Payload(1B) + CRC(1B) - 1 CRC is in length
constexpr size_t   GW_NEGATIVE_RESP_SIZE   = 10;     // Header(8B) + Code(1B) + CRC(1B)
constexpr size_t   GW_MAX_PAYLOAD_SIZE     = 65535;  // 64 KB safety bound
constexpr size_t   GW_LISTEN_BACKLOG       = 32;

constexpr uint8_t  GW_KEY_REQUEST          = 0xAA;   // XOR key for request payload
constexpr uint8_t  GW_KEY_RESPONSE         = 0x55;   // XOR key for response payload

constexpr uint8_t  GW_CRC8_POLY            = 0x07;   // Polynomial x^8 + x^2 + x + 1
constexpr uint8_t  GW_CRC8_INIT            = 0x00;   // Initial CRC value

// Static assertions ensuring exact protocol configuration values (E1.7)
static_assert(DEFAULT_PORT == 13400, "DEFAULT_PORT must be 13400");
static_assert(GW_KEY_REQUEST == 0xAA, "GW_KEY_REQUEST must be 0xAA");
static_assert(GW_KEY_RESPONSE == 0x55, "GW_KEY_RESPONSE must be 0x55");
static_assert(GW_CRC8_POLY == 0x07, "GW_CRC8_POLY must be 0x07");
static_assert(GW_CRC8_INIT == 0x00, "GW_CRC8_INIT must be 0x00");
static_assert(GW_HEADER_SIZE == 8, "GW_HEADER_SIZE must be 8");
static_assert(GW_CRC_SIZE == 1, "GW_CRC_SIZE must be 1");

} // namespace gw

#endif // GW_CONFIG_HPP
