#include <gtest/gtest.h>
#include "packet_parser.hpp"

namespace {

TEST(PacketParserTest, ParseKnownByteSequence) {
    std::vector<uint8_t> frame = {
        0x0E, 0x80,             // SA: 0x0E80
        0x31, 0x08,             // TA: 0x3108
        0x00, 0x00, 0x00, 0x02, // Length: 2
        0xB8,                   // Payload: [0xB8]
        0x21                    // CRC: 0x21
    };

    gw::Packet packet = gw::PacketParser::parse(frame);

    EXPECT_EQ(packet.sourceAddr(), 0x0E80);
    EXPECT_EQ(packet.targetAddr(), 0x3108);
    EXPECT_EQ(packet.length(), 2u);
    EXPECT_EQ(packet.payloadLen(), 1u);
    EXPECT_EQ(packet.payload(), std::vector<uint8_t>{0xB8});
    EXPECT_EQ(packet.crc(), 0x21);
}

TEST(PacketParserTest, RoundTripSerialization) {
    // Exit condition E3.2: parse(packet.serialize()) == packet
    std::vector<gw::Packet> testPackets = {
        gw::Packet(0x0E80, 0x3108, 2, {0xB8}, 0x21),
        gw::Packet(0xE008, 0x1380, 5, {0x01, 0x02, 0x03, 0x04}, 0x55),
        gw::Packet(0x3108, 0x0E80, 2, {0x74}, 0x4B),
        gw::Packet(0x1380, 0xE008, 10, {0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80, 0x90}, 0xAA)
    };

    for (const auto& original : testPackets) {
        std::vector<uint8_t> serialized = original.serialize();
        gw::Packet parsed = gw::PacketParser::parse(serialized);
        EXPECT_TRUE(parsed.equals(original));
    }
}

TEST(PacketParserTest, ThrowsOnUndersizedBuffer) {
    std::vector<uint8_t> tooShort = {0x0E, 0x80, 0x31, 0x08, 0x00, 0x00, 0x00, 0x02}; // only 8 bytes
    EXPECT_THROW(gw::PacketParser::parse(tooShort), std::invalid_argument);

    std::vector<uint8_t> empty;
    EXPECT_THROW(gw::PacketParser::parse(empty), std::invalid_argument);
}

TEST(PacketParserTest, ThrowsOnInvalidLengthField) {
    // Length < 2
    std::vector<uint8_t> badLength = {
        0x0E, 0x80,
        0x31, 0x08,
        0x00, 0x00, 0x00, 0x01, // Length = 1 (invalid, must be >= 2)
        0xB8
    };
    EXPECT_THROW(gw::PacketParser::parse(badLength), std::invalid_argument);
}

TEST(PacketParserTest, ThrowsOnLengthMismatch) {
    // Length says 3 (requires 8 + 3 = 11 bytes), but buffer has 10 bytes
    std::vector<uint8_t> mismatched = {
        0x0E, 0x80,
        0x31, 0x08,
        0x00, 0x00, 0x00, 0x03,
        0xB8, 0x21
    };
    EXPECT_THROW(gw::PacketParser::parse(mismatched), std::invalid_argument);
}

} // namespace
