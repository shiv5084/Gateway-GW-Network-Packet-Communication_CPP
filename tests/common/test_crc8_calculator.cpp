#include <gtest/gtest.h>
#include "crc8_calculator.hpp"
#include <type_traits>
#include <vector>

using namespace gw;

class Crc8CalculatorTest : public ::testing::Test {
protected:
    Crc8Calculator calculator; // default: poly=0x07, init=0x00
};

TEST_F(Crc8CalculatorTest, RuleOfZeroTypeTraits) {
    EXPECT_TRUE(std::is_copy_constructible<Crc8Calculator>::value);
    EXPECT_TRUE(std::is_copy_assignable<Crc8Calculator>::value);
    EXPECT_TRUE(std::is_move_constructible<Crc8Calculator>::value);
    EXPECT_TRUE(std::is_move_assignable<Crc8Calculator>::value);
}

TEST_F(Crc8CalculatorTest, DefaultConstructorParameters) {
    EXPECT_EQ(calculator.getPolynomial(), 0x07);
    EXPECT_EQ(calculator.getInitialValue(), 0x00);

    Crc8Calculator customCalc(0x1D, 0xFF);
    EXPECT_EQ(customCalc.getPolynomial(), 0x1D);
    EXPECT_EQ(customCalc.getInitialValue(), 0xFF);
}

TEST_F(Crc8CalculatorTest, EmptyBufferReturnsInitialValue) {
    EXPECT_EQ(calculator.compute(nullptr, 0), 0x00);

    std::vector<uint8_t> emptyVec;
    EXPECT_EQ(calculator.compute(emptyVec), 0x00);

    Crc8Calculator customCalc(0x07, 0xAA);
    EXPECT_EQ(customCalc.compute(nullptr, 0), 0xAA);
}

TEST_F(Crc8CalculatorTest, SingleByteZero) {
    uint8_t zero = 0x00;
    EXPECT_EQ(calculator.compute(&zero, 1), 0x00);
}

TEST_F(Crc8CalculatorTest, SingleByteB8) {
    // 0xB8 with poly 0x07, init 0x00 produces 0x21
    uint8_t byteB8 = 0xB8;
    EXPECT_EQ(calculator.compute(&byteB8, 1), 0x21);

    std::vector<uint8_t> vecB8 = {0xB8};
    EXPECT_EQ(calculator.compute(vecB8), 0x21);
}

TEST_F(Crc8CalculatorTest, SingleByte74) {
    // 0x74 with poly 0x07, init 0x00 produces 0x4B
    uint8_t byte74 = 0x74;
    EXPECT_EQ(calculator.compute(&byte74, 1), 0x4B);

    std::vector<uint8_t> vec74 = {0x74};
    EXPECT_EQ(calculator.compute(vec74), 0x4B);
}

TEST_F(Crc8CalculatorTest, MultiByteSequence) {
    std::vector<uint8_t> data = {0x01, 0x02, 0x03, 0x04};
    uint8_t crc1 = calculator.compute(data.data(), data.size());
    uint8_t crc2 = calculator.compute(data);
    EXPECT_EQ(crc1, crc2);
    EXPECT_NE(crc1, 0x00);
}

TEST_F(Crc8CalculatorTest, AllOnesSequence) {
    std::vector<uint8_t> allOnes = {0xFF, 0xFF, 0xFF, 0xFF};
    uint8_t crc = calculator.compute(allOnes);
    EXPECT_EQ(crc, calculator.compute(allOnes.data(), allOnes.size()));
}

TEST_F(Crc8CalculatorTest, PureFunctionNoSideEffects) {
    std::vector<uint8_t> original = {0xB8, 0x54, 0x12, 0x34};
    std::vector<uint8_t> copy = original;

    uint8_t res1 = calculator.compute(original);
    uint8_t res2 = calculator.compute(original);

    EXPECT_EQ(res1, res2);
    EXPECT_EQ(original, copy); // buffer was not modified
}
