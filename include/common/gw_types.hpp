#ifndef GW_TYPES_HPP
#define GW_TYPES_HPP

#include <cstdint>
#include <string>

namespace gw {

/**
 * @brief Failure codes sent in negative responses.
 *
 * Values defined by protocol specification:
 * 0x01 - Source Address Invalid
 * 0x02 - Target Address Invalid
 * 0x04 - Integrity Failure (CRC mismatch)
 * 0x08 - Payload Length Mismatch
 */
enum class FailureCode : uint8_t {
    None               = 0x00,
    SourceAddrInvalid  = 0x01,
    TargetAddrInvalid  = 0x02,
    IntegrityFailure   = 0x04,
    LengthMismatch     = 0x08
};

// Static assertions ensuring exact protocol values (E1.6)
static_assert(static_cast<uint8_t>(FailureCode::None) == 0x00, "FailureCode::None must be 0x00");
static_assert(static_cast<uint8_t>(FailureCode::SourceAddrInvalid) == 0x01, "FailureCode::SourceAddrInvalid must be 0x01");
static_assert(static_cast<uint8_t>(FailureCode::TargetAddrInvalid) == 0x02, "FailureCode::TargetAddrInvalid must be 0x02");
static_assert(static_cast<uint8_t>(FailureCode::IntegrityFailure) == 0x04, "FailureCode::IntegrityFailure must be 0x04");
static_assert(static_cast<uint8_t>(FailureCode::LengthMismatch) == 0x08, "FailureCode::LengthMismatch must be 0x08");

/**
 * @brief Response packet classification.
 */
enum class ResponseType {
    Positive,
    Negative
};

/**
 * @brief Convert FailureCode enum to human-readable string.
 */
inline const char* failureCodeToString(FailureCode code) noexcept {
    switch (code) {
        case FailureCode::None:              return "None";
        case FailureCode::SourceAddrInvalid: return "SourceAddrInvalid (0x01)";
        case FailureCode::TargetAddrInvalid: return "TargetAddrInvalid (0x02)";
        case FailureCode::IntegrityFailure:  return "IntegrityFailure (0x04)";
        case FailureCode::LengthMismatch:    return "LengthMismatch (0x08)";
        default:                             return "UnknownFailureCode";
    }
}

/**
 * @brief Protocol address constants.
 */
constexpr uint16_t GW_ADDR_NODE_PRIMARY   = 0x0E80;
constexpr uint16_t GW_ADDR_NODE_SECONDARY = 0xE008;
constexpr uint16_t GW_ADDR_GW_PRIMARY     = 0x3108;
constexpr uint16_t GW_ADDR_GW_SECONDARY   = 0x1380;

/**
 * @brief Check if address is a valid Source Address for inbound requests.
 */
inline bool isValidSourceAddress(uint16_t addr) noexcept {
    return (addr == GW_ADDR_NODE_PRIMARY || addr == GW_ADDR_NODE_SECONDARY);
}

/**
 * @brief Check if address is a valid Target Address for inbound requests.
 */
inline bool isValidTargetAddress(uint16_t addr) noexcept {
    return (addr == GW_ADDR_GW_PRIMARY || addr == GW_ADDR_GW_SECONDARY);
}

} // namespace gw

#endif // GW_TYPES_HPP
