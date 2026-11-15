#include <gtest/gtest.h>
#include "source_address_validator.hpp"

namespace {

TEST(SourceAddressValidatorTest, ValidSourceAddressesReturnNone) {
    gw::SourceAddressValidator validator;

    // Node Primary: 0x0E80
    gw::Packet pPrimary(0x0E80, 0x3108, 2, {0xB8}, 0x21);
    EXPECT_EQ(validator.validate(pPrimary), gw::FailureCode::None);

    // Node Secondary: 0xE008
    gw::Packet pSecondary(0xE008, 0x3108, 2, {0xB8}, 0x21);
    EXPECT_EQ(validator.validate(pSecondary), gw::FailureCode::None);
}

TEST(SourceAddressValidatorTest, InvalidSourceAddressReturnsSourceAddrInvalid) {
    gw::SourceAddressValidator validator;

    // 0xFFFF is not valid
    gw::Packet pInvalid(0xFFFF, 0x3108, 2, {0xB8}, 0x21);
    EXPECT_EQ(validator.validate(pInvalid), gw::FailureCode::SourceAddrInvalid);

    // 0x0000 is not valid
    gw::Packet pZero(0x0000, 0x3108, 2, {0xB8}, 0x21);
    EXPECT_EQ(validator.validate(pZero), gw::FailureCode::SourceAddrInvalid);

    // GW addresses (0x3108, 0x1380) are not valid as Source Addresses for inbound requests
    gw::Packet pGwAsSa(0x3108, 0x3108, 2, {0xB8}, 0x21);
    EXPECT_EQ(validator.validate(pGwAsSa), gw::FailureCode::SourceAddrInvalid);
}

} // namespace
