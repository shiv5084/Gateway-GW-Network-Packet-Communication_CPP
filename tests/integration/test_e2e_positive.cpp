#include <gtest/gtest.h>
#include "gateway_server.hpp"
#include "tcp_client.hpp"
#include "request_builder.hpp"
#include "response_parser.hpp"
#include "xor_crypto_strategy.hpp"
#include "crc8_calculator.hpp"
#include "gw_config.hpp"
#include "platform_socket.hpp"
#include <thread>
#include <chrono>
#include <vector>

namespace {

constexpr uint16_t POS_TEST_PORT = 13430;

class E2EPositiveTest : public ::testing::Test {
protected:
    static void SetUpTestSuite() {
        gw::PlatformSocket::initializePlatform();
        serverThread_ = std::thread([]() {
            server_ = new gw::GatewayServer(POS_TEST_PORT);
            server_->start();
        });
        std::this_thread::sleep_for(std::chrono::milliseconds(250));
    }

    static void TearDownTestSuite() {
        if (server_ != nullptr) {
            server_->stop();
        }
        if (serverThread_.joinable()) {
            serverThread_.join();
        }
        delete server_;
        server_ = nullptr;
    }

    static std::thread serverThread_;
    static gw::GatewayServer* server_;

    gw::XorCryptoStrategy reqCrypto_{gw::GW_KEY_REQUEST};
    gw::XorCryptoStrategy respCrypto_{gw::GW_KEY_RESPONSE};
    gw::Crc8Calculator crcCalc_;
    gw::RequestBuilder builder_{reqCrypto_, crcCalc_};
    gw::ResponseParser parser_{respCrypto_, crcCalc_};
};

std::thread E2EPositiveTest::serverThread_;
gw::GatewayServer* E2EPositiveTest::server_ = nullptr;

// Task P6.1: Single-byte payload
TEST_F(E2EPositiveTest, SingleBytePayload_12_Becomes_21) {
    gw::TcpClient client;
    client.connect("127.0.0.1", POS_TEST_PORT);

    std::vector<uint8_t> frame = builder_.build(gw::GW_ADDR_NODE_PRIMARY, gw::GW_ADDR_GW_PRIMARY, {0x12});
    client.sendFrame(frame);

    std::vector<uint8_t> respBytes = client.receiveFrame();
    gw::ClientResponse resp = parser_.parse(respBytes);

    EXPECT_EQ(resp.type, gw::ResponseType::Positive);
    EXPECT_EQ(resp.sourceAddr, gw::GW_ADDR_GW_PRIMARY);
    EXPECT_EQ(resp.targetAddr, gw::GW_ADDR_NODE_PRIMARY);
    EXPECT_EQ(resp.failureCode, gw::FailureCode::None);
    ASSERT_EQ(resp.decryptedPayload.size(), 1u);
    EXPECT_EQ(resp.decryptedPayload[0], 0x21);
}

// Task P6.2: Multi-byte payload
TEST_F(E2EPositiveTest, MultiBytePayload_12_34_AB_Becomes_21_43_BA) {
    gw::TcpClient client;
    client.connect("127.0.0.1", POS_TEST_PORT);

    std::vector<uint8_t> payload = {0x12, 0x34, 0xAB};
    std::vector<uint8_t> frame = builder_.build(gw::GW_ADDR_NODE_PRIMARY, gw::GW_ADDR_GW_PRIMARY, payload);
    client.sendFrame(frame);

    std::vector<uint8_t> respBytes = client.receiveFrame();
    gw::ClientResponse resp = parser_.parse(respBytes);

    EXPECT_EQ(resp.type, gw::ResponseType::Positive);
    EXPECT_EQ(resp.failureCode, gw::FailureCode::None);
    std::vector<uint8_t> expected = {0x21, 0x43, 0xBA};
    EXPECT_EQ(resp.decryptedPayload, expected);
}

// Task P6.4: Edge payloads
TEST_F(E2EPositiveTest, EdgePayloads_Zero_FF_F0_0F) {
    gw::TcpClient client;
    client.connect("127.0.0.1", POS_TEST_PORT);

    // 0x00 -> 0x00
    {
        std::vector<uint8_t> frame = builder_.build(gw::GW_ADDR_NODE_PRIMARY, gw::GW_ADDR_GW_PRIMARY, {0x00});
        client.sendFrame(frame);
        gw::ClientResponse resp = parser_.parse(client.receiveFrame());
        EXPECT_EQ(resp.type, gw::ResponseType::Positive);
        ASSERT_EQ(resp.decryptedPayload.size(), 1u);
        EXPECT_EQ(resp.decryptedPayload[0], 0x00);
    }

    // 0xFF -> 0xFF
    {
        std::vector<uint8_t> frame = builder_.build(gw::GW_ADDR_NODE_PRIMARY, gw::GW_ADDR_GW_PRIMARY, {0xFF});
        client.sendFrame(frame);
        gw::ClientResponse resp = parser_.parse(client.receiveFrame());
        EXPECT_EQ(resp.type, gw::ResponseType::Positive);
        ASSERT_EQ(resp.decryptedPayload.size(), 1u);
        EXPECT_EQ(resp.decryptedPayload[0], 0xFF);
    }

    // 0xF0 -> 0x0F
    {
        std::vector<uint8_t> frame = builder_.build(gw::GW_ADDR_NODE_PRIMARY, gw::GW_ADDR_GW_PRIMARY, {0xF0});
        client.sendFrame(frame);
        gw::ClientResponse resp = parser_.parse(client.receiveFrame());
        EXPECT_EQ(resp.type, gw::ResponseType::Positive);
        ASSERT_EQ(resp.decryptedPayload.size(), 1u);
        EXPECT_EQ(resp.decryptedPayload[0], 0x0F);
    }

    // 0x0F -> 0xF0
    {
        std::vector<uint8_t> frame = builder_.build(gw::GW_ADDR_NODE_PRIMARY, gw::GW_ADDR_GW_PRIMARY, {0x0F});
        client.sendFrame(frame);
        gw::ClientResponse resp = parser_.parse(client.receiveFrame());
        EXPECT_EQ(resp.type, gw::ResponseType::Positive);
        ASSERT_EQ(resp.decryptedPayload.size(), 1u);
        EXPECT_EQ(resp.decryptedPayload[0], 0xF0);
    }
}

// Task P6.10: Multiple sequential requests on the same connection
TEST_F(E2EPositiveTest, MultipleSequentialRequestsOnSameConnection) {
    gw::TcpClient client;
    client.connect("127.0.0.1", POS_TEST_PORT);

    const uint8_t testInputs[10] = {
        0x12, 0x23, 0x34, 0x41, 0x67, 0x78, 0x89, 0x9A, 0xAB, 0xBC
    };

    for (int i = 0; i < 10; ++i) {
        uint8_t inputByte = testInputs[i];
        uint8_t expectedSwapped = static_cast<uint8_t>((inputByte >> 4) | (inputByte << 4));

        std::vector<uint8_t> frame = builder_.build(gw::GW_ADDR_NODE_PRIMARY, gw::GW_ADDR_GW_PRIMARY, {inputByte});
        client.sendFrame(frame);

        std::vector<uint8_t> respBytes = client.receiveFrame();
        gw::ClientResponse resp = parser_.parse(respBytes);

        EXPECT_EQ(resp.type, gw::ResponseType::Positive);
        EXPECT_EQ(resp.failureCode, gw::FailureCode::None);
        ASSERT_EQ(resp.decryptedPayload.size(), 1u);
        EXPECT_EQ(resp.decryptedPayload[0], expectedSwapped);
    }
}

} // namespace
