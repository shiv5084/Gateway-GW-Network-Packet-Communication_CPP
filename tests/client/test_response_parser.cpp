#include <gtest/gtest.h>
#include "response_parser.hpp"
#include "xor_crypto_strategy.hpp"
#include "crc8_calculator.hpp"
#include "response_factory.hpp"
#include "gw_config.hpp"

namespace {

class ResponseParserTest : public ::testing::Test {
protected:
    gw::XorCryptoStrategy responseCrypto_{gw::GW_KEY_RESPONSE}; // 0x55
    gw::Crc8Calculator crcCalc_;
    gw::ResponseParser parser_{responseCrypto_, crcCalc_};
    gw::ResponseFactory factory_{responseCrypto_, crcCalc_};
};

TEST_F(ResponseParserTest, ParsePositiveResponseSingleByte) {
    // Exit condition E3.11:
    // Positive response frame with encrypted byte 0x74 (= 0x21 ^ 0x55) and CRC 0x4B
    std::vector<uint8_t> frame = {
        0x31, 0x08,             // SA: 0x3108
        0x0E, 0x80,             // TA: 0x0E80
        0x00, 0x00, 0x00, 0x02, // Length: 2
        0x74,                   // Encrypted: 0x74
        0x4B                    // CRC: 0x4B
    };

    gw::ClientResponse resp = parser_.parse(frame);

    EXPECT_EQ(resp.type, gw::ResponseType::Positive);
    EXPECT_EQ(resp.sourceAddr, 0x3108);
    EXPECT_EQ(resp.targetAddr, 0x0E80);
    EXPECT_EQ(resp.failureCode, gw::FailureCode::None);
    EXPECT_EQ(resp.decryptedPayload, std::vector<uint8_t>{0x21});
}

TEST_F(ResponseParserTest, ParsePositiveResponseMultiByte) {
    // Multi-byte response: raw [0x10, 0x20] -> encrypted [0x10^0x55, 0x20^0x55] = [0x45, 0x75]
    gw::Packet req(0x0E80, 0x3108, 2, {0xB8}, 0x21);
    std::vector<uint8_t> frame = factory_.create(req, gw::FailureCode::None, {0x10, 0x20});

    gw::ClientResponse resp = parser_.parse(frame);
    EXPECT_EQ(resp.type, gw::ResponseType::Positive);
    EXPECT_EQ(resp.failureCode, gw::FailureCode::None);
    std::vector<uint8_t> expected = {0x10, 0x20};
    EXPECT_EQ(resp.decryptedPayload, expected);
}

TEST_F(ResponseParserTest, ParseNegativeResponseTargetAddrInvalid) {
    gw::Packet req(0x0E80, 0x9999, 2, {0xB8}, 0x21);
    std::vector<uint8_t> frame = factory_.create(req, gw::FailureCode::TargetAddrInvalid);

    gw::ClientResponse resp = parser_.parse(frame);

    EXPECT_EQ(resp.type, gw::ResponseType::Negative);
    EXPECT_EQ(resp.failureCode, gw::FailureCode::TargetAddrInvalid);
    EXPECT_TRUE(resp.decryptedPayload.empty());
}

TEST_F(ResponseParserTest, ParseAllNegativeResponseCodes) {
    gw::Packet req(0x0E80, 0x3108, 2, {0xB8}, 0x21);
    gw::FailureCode codes[] = {
        gw::FailureCode::SourceAddrInvalid,
        gw::FailureCode::TargetAddrInvalid,
        gw::FailureCode::IntegrityFailure,
        gw::FailureCode::LengthMismatch
    };

    for (gw::FailureCode code : codes) {
        std::vector<uint8_t> frame = factory_.create(req, code);
        gw::ClientResponse resp = parser_.parse(frame);

        EXPECT_EQ(resp.type, gw::ResponseType::Negative);
        EXPECT_EQ(resp.failureCode, code);
        EXPECT_TRUE(resp.decryptedPayload.empty());
    }
}

TEST_F(ResponseParserTest, ThrowsOnCorruptedCrc) {
    std::vector<uint8_t> frame = {
        0x31, 0x08,
        0x0E, 0x80,
        0x00, 0x00, 0x00, 0x02,
        0x74,
        0xFF // Corrupted CRC (expected 0x4B)
    };

    EXPECT_THROW(parser_.parse(frame), std::runtime_error);
}

} // namespace
