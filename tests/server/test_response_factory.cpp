#include <gtest/gtest.h>
#include "response_factory.hpp"
#include "xor_crypto_strategy.hpp"
#include "crc8_calculator.hpp"
#include "gw_config.hpp"

namespace {

class ResponseFactoryTest : public ::testing::Test {
protected:
    gw::XorCryptoStrategy responseCrypto_{gw::GW_KEY_RESPONSE}; // 0x55
    gw::Crc8Calculator crcCalc_;
    gw::ResponseFactory factory_{responseCrypto_, crcCalc_};
};

TEST_F(ResponseFactoryTest, PositiveResponseProducesExpectedFrame) {
    // Exit condition E3.8:
    // Request SA=0x0E80, TA=0x3108.
    // Transformed payload [0x21].
    // Swapped SA=0x3108, TA=0x0E80.
    // Encrypted byte: 0x21 ^ 0x55 = 0x74.
    // CRC over [0x74] is 0x4B.
    gw::Packet req(0x0E80, 0x3108, 2, {0xB8}, 0x21);
    std::vector<uint8_t> frame = factory_.create(req, gw::FailureCode::None, {0x21});

    std::vector<uint8_t> expected = {
        0x31, 0x08,             // Swapped SA
        0x0E, 0x80,             // Swapped TA
        0x00, 0x00, 0x00, 0x02, // Length: 2
        0x74,                   // Encrypted payload
        0x4B                    // CRC
    };

    EXPECT_EQ(frame, expected);
}

TEST_F(ResponseFactoryTest, NegativeResponseTargetAddrInvalidProducesExact10ByteFrame) {
    // Exit condition E3.9:
    // Negative response for TargetAddrInvalid produces exactly 10-byte frame
    // with unencrypted 0x02 failure code.
    gw::Packet req(0x0E80, 0x9999, 2, {0xB8}, 0x21);
    std::vector<uint8_t> frame = factory_.create(req, gw::FailureCode::TargetAddrInvalid);

    ASSERT_EQ(frame.size(), 10u);
    EXPECT_EQ(frame[0], 0x99); // Swapped SA (high byte)
    EXPECT_EQ(frame[1], 0x99); // Swapped SA (low byte)
    EXPECT_EQ(frame[2], 0x0E); // Swapped TA (high byte)
    EXPECT_EQ(frame[3], 0x80); // Swapped TA (low byte)
    EXPECT_EQ(frame[4], 0x00); // Length (big endian 2)
    EXPECT_EQ(frame[5], 0x00);
    EXPECT_EQ(frame[6], 0x00);
    EXPECT_EQ(frame[7], 0x02);
    EXPECT_EQ(frame[8], 0x02); // Unencrypted FailureCode::TargetAddrInvalid
    uint8_t expectedCrc = crcCalc_.compute(&frame[8], 1);
    EXPECT_EQ(frame[9], expectedCrc); // CRC over unencrypted failure code
}

TEST_F(ResponseFactoryTest, AllNegativeFailureCodesProduceValidFrames) {
    gw::Packet req(0x0E80, 0x3108, 2, {0xB8}, 0x21);
    gw::FailureCode codes[] = {
        gw::FailureCode::SourceAddrInvalid,
        gw::FailureCode::TargetAddrInvalid,
        gw::FailureCode::IntegrityFailure,
        gw::FailureCode::LengthMismatch
    };

    for (gw::FailureCode code : codes) {
        std::vector<uint8_t> frame = factory_.create(req, code);
        ASSERT_EQ(frame.size(), 10u);
        EXPECT_EQ(frame[8], static_cast<uint8_t>(code));
        uint8_t expectedCrc = crcCalc_.compute(&frame[8], 1);
        EXPECT_EQ(frame[9], expectedCrc);
    }
}

} // namespace
