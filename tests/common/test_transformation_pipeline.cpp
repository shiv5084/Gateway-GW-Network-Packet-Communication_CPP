#include <gtest/gtest.h>
#include "crc8_calculator.hpp"
#include "xor_crypto_strategy.hpp"
#include "nibble_swap_transform.hpp"
#include <vector>

using namespace gw;

class TransformationPipelineTest : public ::testing::Test {
protected:
    XorCryptoStrategy requestCrypto{0xAA};
    XorCryptoStrategy responseCrypto{0x55};
    NibbleSwapTransform nibbleSwap;
    Crc8Calculator crcCalculator;
};

// ============================================================================
// E2.6: Golden Test Vector Trace (Single-Byte: 0x12)
// ============================================================================
TEST_F(TransformationPipelineTest, GoldenSingleByteTrace) {
    // 1. Client side: raw payload
    std::vector<uint8_t> clientPayload = {0x12};

    // 2. Client side: encrypt with key 0xAA
    requestCrypto.process(clientPayload);
    ASSERT_EQ(clientPayload.size(), 1u);
    EXPECT_EQ(clientPayload[0], 0xB8); // [0x12] XOR 0xAA = [0xB8]

    // 3. Client side: compute CRC-8 over encrypted payload
    uint8_t clientCrc = crcCalculator.compute(clientPayload);
    EXPECT_EQ(clientCrc, 0x21); // CRC-8([0xB8]) = 0x21

    // 4. Server side: receive encrypted payload, verify CRC
    EXPECT_EQ(crcCalculator.compute(clientPayload), clientCrc);

    // 5. Server side: decrypt with key 0xAA
    std::vector<uint8_t> serverPayload = clientPayload;
    requestCrypto.process(serverPayload);
    EXPECT_EQ(serverPayload[0], 0x12); // Restored original 0x12

    // 6. Server side: transform payload (nibble swap)
    nibbleSwap.apply(serverPayload);
    EXPECT_EQ(serverPayload[0], 0x21); // 0x12 -> 0x21

    // 7. Server side: encrypt with response key 0x55
    responseCrypto.process(serverPayload);
    EXPECT_EQ(serverPayload[0], 0x74); // 0x21 XOR 0x55 = 0x74

    // 8. Server side: compute response CRC-8 over encrypted response payload
    uint8_t serverResponseCrc = crcCalculator.compute(serverPayload);
    EXPECT_EQ(serverResponseCrc, 0x4B); // CRC-8([0x74]) = 0x4B

    // 9. Client side: receive response, verify CRC, decrypt with 0x55
    EXPECT_EQ(crcCalculator.compute(serverPayload), serverResponseCrc);
    responseCrypto.process(serverPayload);
    EXPECT_EQ(serverPayload[0], 0x21); // Final received payload is 0x21
}

// ============================================================================
// Multi-Byte Pipeline Trace
// ============================================================================
TEST_F(TransformationPipelineTest, MultiByteTrace) {
    // 1. Multi-byte client input
    std::vector<uint8_t> payload = {0x12, 0x34, 0xAB};
    const std::vector<uint8_t> expectedTransformed = {0x21, 0x43, 0xBA};

    // 2. Client encryption (0xAA)
    requestCrypto.process(payload);
    EXPECT_EQ(payload, (std::vector<uint8_t>{0xB8, 0x9E, 0x01}));
    uint8_t reqCrc = crcCalculator.compute(payload);

    // 3. Server verification and decryption
    EXPECT_EQ(crcCalculator.compute(payload), reqCrc);
    requestCrypto.process(payload);
    EXPECT_EQ(payload, (std::vector<uint8_t>{0x12, 0x34, 0xAB}));

    // 4. Server nibble swap
    nibbleSwap.apply(payload);
    EXPECT_EQ(payload, expectedTransformed);

    // 5. Server response encryption (0x55)
    responseCrypto.process(payload);
    EXPECT_EQ(payload, (std::vector<uint8_t>{0x74, 0x16, 0xEF}));
    uint8_t respCrc = crcCalculator.compute(payload);

    // 6. Client verification and decryption
    EXPECT_EQ(crcCalculator.compute(payload), respCrc);
    responseCrypto.process(payload);
    EXPECT_EQ(payload, expectedTransformed);
}

// ============================================================================
// Edge-Case Payloads: 0x00, 0xFF, Symmetric Nibbles
// ============================================================================
TEST_F(TransformationPipelineTest, SymmetricAndEdgePayloads) {
    std::vector<uint8_t> edgePayloads = {0x00, 0xFF, 0x55, 0xAA, 0xF0, 0x0F};

    for (uint8_t originalByte : edgePayloads) {
        std::vector<uint8_t> buf = {originalByte};

        // Encrypt with 0xAA
        requestCrypto.process(buf);
        EXPECT_EQ(buf[0], static_cast<uint8_t>(originalByte ^ 0xAA));

        // Decrypt with 0xAA
        requestCrypto.process(buf);
        EXPECT_EQ(buf[0], originalByte);

        // Nibble swap
        uint8_t expectedSwapped = static_cast<uint8_t>(((originalByte & 0x0F) << 4) | ((originalByte & 0xF0) >> 4));
        nibbleSwap.apply(buf);
        EXPECT_EQ(buf[0], expectedSwapped);

        // Encrypt with 0x55
        responseCrypto.process(buf);
        EXPECT_EQ(buf[0], static_cast<uint8_t>(expectedSwapped ^ 0x55));

        // Decrypt with 0x55
        responseCrypto.process(buf);
        EXPECT_EQ(buf[0], expectedSwapped);
    }
}
