#include <gtest/gtest.h>
#include "length_validator.hpp"
#include "source_address_validator.hpp"
#include "target_address_validator.hpp"
#include "crc_validator.hpp"

namespace {

class ValidationChainTest : public ::testing::Test {
protected:
    void SetUp() override {
        // Wire the Chain of Responsibility:
        // LengthValidator -> SourceAddressValidator -> TargetAddressValidator -> CrcValidator
        lengthVal_.setNext(&saVal_)->setNext(&taVal_)->setNext(&crcVal_);
    }

    gw::Crc8Calculator crcCalc_;
    gw::LengthValidator lengthVal_;
    gw::SourceAddressValidator saVal_;
    gw::TargetAddressValidator taVal_;
    gw::CrcValidator crcVal_{crcCalc_};
};

TEST_F(ValidationChainTest, FullyValidPacketReturnsNone) {
    gw::Packet validPacket(0x0E80, 0x3108, 2, {0xB8}, 0x21);
    EXPECT_EQ(lengthVal_.validate(validPacket), gw::FailureCode::None);
}

TEST_F(ValidationChainTest, PrecedenceBadSaAndBadCrcReturnsSourceAddrInvalid) {
    // Exit condition E3.7:
    // Packet has invalid SA (0xFFFF) AND invalid CRC (0x99 != 0x21)
    // Precedence: SA validator is evaluated before CRC validator.
    // Must return SourceAddrInvalid (0x01), NOT IntegrityFailure (0x04).
    gw::Packet dualFailure(0xFFFF, 0x3108, 2, {0xB8}, 0x99);
    EXPECT_EQ(lengthVal_.validate(dualFailure), gw::FailureCode::SourceAddrInvalid);
}

TEST_F(ValidationChainTest, PrecedenceBadLengthAndBadSaReturnsLengthMismatch) {
    // Length is evaluated before SA
    gw::Packet dualFailure(0xFFFF, 0x3108, 10, {0xB8}, 0x21);
    EXPECT_EQ(lengthVal_.validate(dualFailure), gw::FailureCode::LengthMismatch);
}

TEST_F(ValidationChainTest, PrecedenceBadSaAndBadTaReturnsSourceAddrInvalid) {
    // SA is evaluated before TA
    gw::Packet dualFailure(0xFFFF, 0x9999, 2, {0xB8}, 0x21);
    EXPECT_EQ(lengthVal_.validate(dualFailure), gw::FailureCode::SourceAddrInvalid);
}

TEST_F(ValidationChainTest, PrecedenceBadTaAndBadCrcReturnsTargetAddrInvalid) {
    // TA is evaluated before CRC
    gw::Packet dualFailure(0x0E80, 0x9999, 2, {0xB8}, 0x99);
    EXPECT_EQ(lengthVal_.validate(dualFailure), gw::FailureCode::TargetAddrInvalid);
}

TEST_F(ValidationChainTest, OnlyCrcBadReturnsIntegrityFailure) {
    gw::Packet badCrc(0x0E80, 0x3108, 2, {0xB8}, 0x00);
    EXPECT_EQ(lengthVal_.validate(badCrc), gw::FailureCode::IntegrityFailure);
}

} // namespace
