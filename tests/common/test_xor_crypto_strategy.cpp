#include <gtest/gtest.h>
#include "xor_crypto_strategy.hpp"
#include <type_traits>
#include <vector>
#include <memory>

using namespace gw;

TEST(XorCryptoStrategyTest, InterfaceProperties) {
    EXPECT_TRUE(std::is_abstract<ICryptoStrategy>::value);
    EXPECT_TRUE(std::has_virtual_destructor<ICryptoStrategy>::value);
}

TEST(XorCryptoStrategyTest, RuleOfZeroTypeTraits) {
    EXPECT_TRUE(std::is_copy_constructible<XorCryptoStrategy>::value);
    EXPECT_TRUE(std::is_copy_assignable<XorCryptoStrategy>::value);
    EXPECT_TRUE(std::is_move_constructible<XorCryptoStrategy>::value);
    EXPECT_TRUE(std::is_move_assignable<XorCryptoStrategy>::value);
}

TEST(XorCryptoStrategyTest, KeyAccessor) {
    XorCryptoStrategy strategyAA(0xAA);
    EXPECT_EQ(strategyAA.getKey(), 0xAA);

    XorCryptoStrategy strategy55(0x55);
    EXPECT_EQ(strategy55.getKey(), 0x55);
}

TEST(XorCryptoStrategyTest, ProcessKeyAA_SingleByte) {
    XorCryptoStrategy strategy(0xAA);

    uint8_t data = 0x12;
    strategy.process(&data, 1);
    EXPECT_EQ(data, 0xB8); // 0x12 ^ 0xAA = 0xB8

    // Symmetrical: applying again restores original
    strategy.process(&data, 1);
    EXPECT_EQ(data, 0x12);
}

TEST(XorCryptoStrategyTest, ProcessKey55_SingleByte) {
    XorCryptoStrategy strategy(0x55);

    uint8_t data = 0x21;
    strategy.process(&data, 1);
    EXPECT_EQ(data, 0x74); // 0x21 ^ 0x55 = 0x74

    // Symmetrical: applying again restores original
    strategy.process(&data, 1);
    EXPECT_EQ(data, 0x21);
}

TEST(XorCryptoStrategyTest, MultiByteTransformation) {
    XorCryptoStrategy strategy(0xAA);

    std::vector<uint8_t> payload = {0x12, 0x34, 0xAB};
    std::vector<uint8_t> expected = {0xB8, 0x9E, 0x01};

    strategy.process(payload);
    EXPECT_EQ(payload, expected);

    strategy.process(payload);
    std::vector<uint8_t> restored = {0x12, 0x34, 0xAB};
    EXPECT_EQ(payload, restored);
}

TEST(XorCryptoStrategyTest, EmptyAndNullBufferHandling) {
    XorCryptoStrategy strategy(0xAA);

    // Should not crash or modify invalid pointers
    strategy.process(nullptr, 0);
    strategy.process(nullptr, 10);

    std::vector<uint8_t> emptyVec;
    strategy.process(emptyVec);
    EXPECT_TRUE(emptyVec.empty());
}

TEST(XorCryptoStrategyTest, PolymorphicDispatch) {
    std::unique_ptr<ICryptoStrategy> strategy = std::unique_ptr<ICryptoStrategy>(new XorCryptoStrategy(0xAA));
    EXPECT_EQ(strategy->getKey(), 0xAA);

    uint8_t byte = 0x12;
    strategy->process(&byte, 1);
    EXPECT_EQ(byte, 0xB8);
}
