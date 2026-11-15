#include <gtest/gtest.h>
#include "nibble_swap_transform.hpp"
#include <type_traits>
#include <vector>
#include <memory>

using namespace gw;

TEST(NibbleSwapTransformTest, InterfaceProperties) {
    EXPECT_TRUE(std::is_abstract<ITransform>::value);
    EXPECT_TRUE(std::has_virtual_destructor<ITransform>::value);
}

TEST(NibbleSwapTransformTest, RuleOfZeroTypeTraits) {
    EXPECT_TRUE(std::is_copy_constructible<NibbleSwapTransform>::value);
    EXPECT_TRUE(std::is_copy_assignable<NibbleSwapTransform>::value);
    EXPECT_TRUE(std::is_move_constructible<NibbleSwapTransform>::value);
    EXPECT_TRUE(std::is_move_assignable<NibbleSwapTransform>::value);
}

TEST(NibbleSwapTransformTest, SingleByteValues) {
    NibbleSwapTransform transform;

    uint8_t b1 = 0x12;
    transform.apply(&b1, 1);
    EXPECT_EQ(b1, 0x21);

    uint8_t b2 = 0xAB;
    transform.apply(&b2, 1);
    EXPECT_EQ(b2, 0xBA);

    uint8_t b3 = 0x00;
    transform.apply(&b3, 1);
    EXPECT_EQ(b3, 0x00);

    uint8_t b4 = 0xFF;
    transform.apply(&b4, 1);
    EXPECT_EQ(b4, 0xFF);

    uint8_t b5 = 0xF0;
    transform.apply(&b5, 1);
    EXPECT_EQ(b5, 0x0F);

    uint8_t b6 = 0x0F;
    transform.apply(&b6, 1);
    EXPECT_EQ(b6, 0xF0);
}

TEST(NibbleSwapTransformTest, MultiByteSequence) {
    NibbleSwapTransform transform;

    std::vector<uint8_t> data = {0x12, 0x34, 0xAB};
    std::vector<uint8_t> expected = {0x21, 0x43, 0xBA};

    transform.apply(data);
    EXPECT_EQ(data, expected);
}

TEST(NibbleSwapTransformTest, DoubleApplyRestoresOriginal) {
    NibbleSwapTransform transform;

    std::vector<uint8_t> original = {0x12, 0x34, 0xAB, 0x00, 0xFF, 0xF0, 0x0F, 0x74};
    std::vector<uint8_t> data = original;

    transform.apply(data);
    EXPECT_NE(data, original);

    transform.apply(data);
    EXPECT_EQ(data, original);
}

TEST(NibbleSwapTransformTest, EmptyAndNullBuffers) {
    NibbleSwapTransform transform;

    transform.apply(nullptr, 0);
    transform.apply(nullptr, 10);

    std::vector<uint8_t> emptyVec;
    transform.apply(emptyVec);
    EXPECT_TRUE(emptyVec.empty());
}

TEST(NibbleSwapTransformTest, PolymorphicDispatch) {
    std::unique_ptr<ITransform> transform = std::unique_ptr<ITransform>(new NibbleSwapTransform());

    uint8_t val = 0x12;
    transform->apply(&val, 1);
    EXPECT_EQ(val, 0x21);
}
