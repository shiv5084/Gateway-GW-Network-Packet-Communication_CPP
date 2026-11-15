#include <gtest/gtest.h>
#include "length_validator.hpp"

namespace {

TEST(LengthValidatorTest, ValidLengthReturnsNone) {
    gw::LengthValidator validator;
    // length = 2, payload = 1 byte -> length == payload.size() + 1
    gw::Packet validPacket(0x0E80, 0x3108, 2, {0xB8}, 0x21);
    EXPECT_EQ(validator.validate(validPacket), gw::FailureCode::None);

    // Multi-byte payload: length = 4, payload = 3 bytes
    gw::Packet validMulti(0x0E80, 0x3108, 4, {0x11, 0x22, 0x33}, 0x00);
    EXPECT_EQ(validator.validate(validMulti), gw::FailureCode::None);
}

TEST(LengthValidatorTest, LengthLessThanTwoReturnsLengthMismatch) {
    gw::LengthValidator validator;
    // Length < 2
    gw::Packet invalidPacket(0x0E80, 0x3108, 1, {0xB8}, 0x21);
    EXPECT_EQ(validator.validate(invalidPacket), gw::FailureCode::LengthMismatch);
}

TEST(LengthValidatorTest, MismatchedLengthReturnsLengthMismatch) {
    gw::LengthValidator validator;
    // length says 5, but payload has only 1 byte (length != payload.size() + 1)
    gw::Packet mismatched(0x0E80, 0x3108, 5, {0xB8}, 0x21);
    EXPECT_EQ(validator.validate(mismatched), gw::FailureCode::LengthMismatch);
}

} // namespace
