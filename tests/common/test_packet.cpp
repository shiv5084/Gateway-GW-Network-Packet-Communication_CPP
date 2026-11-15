#include <gtest/gtest.h>
#include "packet.hpp"
#include <type_traits>

namespace {

TEST(PacketTest, RuleOfZeroCompliance) {
    // Packet is a regular value type managed entirely by compiler-generated special members
    EXPECT_TRUE(std::is_copy_constructible<gw::Packet>::value);
    EXPECT_TRUE(std::is_move_constructible<gw::Packet>::value);
    EXPECT_TRUE(std::is_copy_assignable<gw::Packet>::value);
    EXPECT_TRUE(std::is_move_assignable<gw::Packet>::value);
    EXPECT_TRUE(std::is_destructible<gw::Packet>::value);
}

TEST(PacketTest, ConstructionAndAccessors) {
    std::vector<uint8_t> payload = {0xB8};
    gw::Packet packet(0x0E80, 0x3108, 2, payload, 0x21);

    EXPECT_EQ(packet.sourceAddr(), 0x0E80);
    EXPECT_EQ(packet.targetAddr(), 0x3108);
    EXPECT_EQ(packet.length(), 2u);
    EXPECT_EQ(packet.payloadLen(), 1u);
    EXPECT_EQ(packet.payload(), payload);
    EXPECT_EQ(packet.crc(), 0x21);
}

TEST(PacketTest, SerializeProducesExpectedBigEndianFrame) {
    // Exit condition E3.1
    // SA=0x0E80, TA=0x3108, payload=[0xB8], CRC=0x21 -> Length = 2
    gw::Packet packet(0x0E80, 0x3108, 2, {0xB8}, 0x21);
    std::vector<uint8_t> expected = {
        0x0E, 0x80, // SA
        0x31, 0x08, // TA
        0x00, 0x00, 0x00, 0x02, // Length
        0xB8,       // Payload
        0x21        // CRC
    };

    std::vector<uint8_t> serialized = packet.serialize();
    EXPECT_EQ(serialized, expected);
}

TEST(PacketTest, MultiBytePayloadSerialization) {
    std::vector<uint8_t> payload = {0x11, 0x22, 0x33, 0x44};
    gw::Packet packet(0xE008, 0x1380, 5, payload, 0x99);

    std::vector<uint8_t> expected = {
        0xE0, 0x08,
        0x13, 0x80,
        0x00, 0x00, 0x00, 0x05,
        0x11, 0x22, 0x33, 0x44,
        0x99
    };

    EXPECT_EQ(packet.serialize(), expected);
}

TEST(PacketTest, EqualityComparison) {
    gw::Packet p1(0x0E80, 0x3108, 2, {0xB8}, 0x21);
    gw::Packet p2(0x0E80, 0x3108, 2, {0xB8}, 0x21);
    gw::Packet pDiffSa(0xE008, 0x3108, 2, {0xB8}, 0x21);
    gw::Packet pDiffTa(0x0E80, 0x1380, 2, {0xB8}, 0x21);
    gw::Packet pDiffPayload(0x0E80, 0x3108, 2, {0xAA}, 0x21);
    gw::Packet pDiffCrc(0x0E80, 0x3108, 2, {0xB8}, 0x22);

    EXPECT_TRUE(p1.equals(p2));
    EXPECT_FALSE(p1.equals(pDiffSa));
    EXPECT_FALSE(p1.equals(pDiffTa));
    EXPECT_FALSE(p1.equals(pDiffPayload));
    EXPECT_FALSE(p1.equals(pDiffCrc));
}

} // namespace
