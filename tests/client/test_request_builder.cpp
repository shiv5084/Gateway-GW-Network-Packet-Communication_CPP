#include <gtest/gtest.h>
#include "request_builder.hpp"
#include "xor_crypto_strategy.hpp"
#include "crc8_calculator.hpp"
#include "packet_parser.hpp"
#include "gw_config.hpp"

namespace {

class RequestBuilderTest : public ::testing::Test {
protected:
    gw::XorCryptoStrategy requestCrypto_{gw::GW_KEY_REQUEST}; // 0xAA
    gw::Crc8Calculator crcCalc_;
    gw::RequestBuilder builder_{requestCrypto_, crcCalc_};
};

TEST_F(RequestBuilderTest, BuildValidSingleByteRequest) {
    // Exit condition E3.10:
    // RequestBuilder::build() for raw [0x12] produces frame matching:
    // [0x0E, 0x80, 0x31, 0x08, 0x00, 0x00, 0x00, 0x02, 0xB8, 0x21]
    std::vector<uint8_t> frame = builder_.build(0x0E80, 0x3108, {0x12});

    std::vector<uint8_t> expected = {
        0x0E, 0x80,             // SA: 0x0E80
        0x31, 0x08,             // TA: 0x3108
        0x00, 0x00, 0x00, 0x02, // Length: 2
        0xB8,                   // Encrypted: 0x12 ^ 0xAA = 0xB8
        0x21                    // CRC-8([0xB8]) = 0x21
    };

    EXPECT_EQ(frame, expected);
}

TEST_F(RequestBuilderTest, BuildMultiByteRequest) {
    std::vector<uint8_t> raw = {0x01, 0x02, 0x03};
    std::vector<uint8_t> frame = builder_.build(0x0E80, 0x3108, raw);

    gw::Packet parsed = gw::PacketParser::parse(frame);
    EXPECT_EQ(parsed.sourceAddr(), 0x0E80);
    EXPECT_EQ(parsed.targetAddr(), 0x3108);
    EXPECT_EQ(parsed.length(), 4u);
    EXPECT_EQ(parsed.payload().size(), 3u);

    // Verify payload encrypted with 0xAA
    EXPECT_EQ(parsed.payload()[0], static_cast<uint8_t>(0x01 ^ 0xAA));
    EXPECT_EQ(parsed.payload()[1], static_cast<uint8_t>(0x02 ^ 0xAA));
    EXPECT_EQ(parsed.payload()[2], static_cast<uint8_t>(0x03 ^ 0xAA));

    uint8_t expectedCrc = crcCalc_.compute(parsed.payload().data(), parsed.payload().size());
    EXPECT_EQ(parsed.crc(), expectedCrc);
}

TEST_F(RequestBuilderTest, BuildInvalidCorruptCrc) {
    std::vector<uint8_t> frame = builder_.buildInvalid(0x0E80, 0x3108, {0x12}, true, false);
    gw::Packet parsed = gw::PacketParser::parse(frame);

    uint8_t expectedCrc = crcCalc_.compute(parsed.payload().data(), parsed.payload().size());
    EXPECT_NE(parsed.crc(), expectedCrc);
}

TEST_F(RequestBuilderTest, BuildInvalidCorruptLength) {
    std::vector<uint8_t> frame = builder_.buildInvalid(0x0E80, 0x3108, {0x12}, false, true);
    // Length in header was increased by 10, so PacketParser will detect size mismatch
    EXPECT_THROW(gw::PacketParser::parse(frame), std::invalid_argument);
}

} // namespace
