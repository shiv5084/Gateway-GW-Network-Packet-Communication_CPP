#include <gtest/gtest.h>
#include "crc_validator.hpp"

namespace {

TEST(CrcValidatorTest, ValidCrcReturnsNone) {
    gw::Crc8Calculator calculator;
    gw::CrcValidator validator(calculator);

    // CRC of [0xB8] is 0x21
    gw::Packet validPacket(0x0E80, 0x3108, 2, {0xB8}, 0x21);
    EXPECT_EQ(validator.validate(validPacket), gw::FailureCode::None);

    // CRC of [0x74] is 0x4B
    gw::Packet validPacket2(0x3108, 0x0E80, 2, {0x74}, 0x4B);
    EXPECT_EQ(validator.validate(validPacket2), gw::FailureCode::None);
}

TEST(CrcValidatorTest, CorruptedCrcReturnsIntegrityFailure) {
    gw::Crc8Calculator calculator;
    gw::CrcValidator validator(calculator);

    // Actual CRC is 0x21, but packet has 0x99
    gw::Packet corrupted(0x0E80, 0x3108, 2, {0xB8}, 0x99);
    EXPECT_EQ(validator.validate(corrupted), gw::FailureCode::IntegrityFailure);
}

} // namespace
