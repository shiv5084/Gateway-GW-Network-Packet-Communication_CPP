#include <gtest/gtest.h>
#include "target_address_validator.hpp"

namespace {

TEST(TargetAddressValidatorTest, ValidTargetAddressesReturnNone) {
    gw::TargetAddressValidator validator;

    // GW Primary: 0x3108
    gw::Packet pPrimary(0x0E80, 0x3108, 2, {0xB8}, 0x21);
    EXPECT_EQ(validator.validate(pPrimary), gw::FailureCode::None);

    // GW Secondary: 0x1380
    gw::Packet pSecondary(0x0E80, 0x1380, 2, {0xB8}, 0x21);
    EXPECT_EQ(validator.validate(pSecondary), gw::FailureCode::None);
}

TEST(TargetAddressValidatorTest, InvalidTargetAddressReturnsTargetAddrInvalid) {
    gw::TargetAddressValidator validator;

    // 0x9999 is not valid
    gw::Packet pInvalid(0x0E80, 0x9999, 2, {0xB8}, 0x21);
    EXPECT_EQ(validator.validate(pInvalid), gw::FailureCode::TargetAddrInvalid);

    // 0x0000 is not valid
    gw::Packet pZero(0x0E80, 0x0000, 2, {0xB8}, 0x21);
    EXPECT_EQ(validator.validate(pZero), gw::FailureCode::TargetAddrInvalid);

    // Node addresses (0x0E80, 0xE008) are not valid as Target Addresses for inbound requests
    gw::Packet pNodeAsTa(0x0E80, 0x0E80, 2, {0xB8}, 0x21);
    EXPECT_EQ(validator.validate(pNodeAsTa), gw::FailureCode::TargetAddrInvalid);
}

} // namespace
