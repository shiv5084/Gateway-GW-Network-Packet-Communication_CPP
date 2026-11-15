#ifndef GW_PACKET_PARSER_HPP
#define GW_PACKET_PARSER_HPP

#include "packet.hpp"
#include <vector>
#include <cstdint>
#include <cstddef>

namespace gw {

/**
 * @brief Static parser class to deserialize byte sequences into Packet objects.
 *
 * Adheres to Rule of Zero: pure static utility class, no instance state.
 */
class PacketParser {
public:
    static Packet parse(const std::vector<uint8_t>& frameData);
    static Packet parse(const uint8_t* data, size_t size);
};

} // namespace gw

#endif // GW_PACKET_PARSER_HPP
