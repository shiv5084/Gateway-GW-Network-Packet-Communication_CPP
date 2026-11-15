#include <gtest/gtest.h>
#include "gateway_server.hpp"
#include "tcp_client.hpp"
#include "request_builder.hpp"
#include "response_parser.hpp"
#include "xor_crypto_strategy.hpp"
#include "crc8_calculator.hpp"
#include "server_metrics.hpp"
#include "gw_config.hpp"
#include "platform_socket.hpp"
#include <thread>
#include <chrono>
#include <vector>

namespace {

constexpr uint16_t TEST_PORT = 13410;

class Phase4NetworkingTest : public ::testing::Test {
protected:
    static void SetUpTestSuite() {
        gw::PlatformSocket::initializePlatform();
        gw::ServerMetrics::instance().reset();

        serverThread_ = std::thread([]() {
            server_ = new gw::GatewayServer(TEST_PORT);
            server_->start();
        });

        // Give server time to bind and listen
        std::this_thread::sleep_for(std::chrono::milliseconds(200));
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
};

std::thread Phase4NetworkingTest::serverThread_;
gw::GatewayServer* Phase4NetworkingTest::server_ = nullptr;

TEST_F(Phase4NetworkingTest, E4_1_ServerIsRunningAndBound) {
    ASSERT_NE(server_, nullptr);
    EXPECT_TRUE(server_->isRunning());
    EXPECT_EQ(server_->getPort(), TEST_PORT);
}

TEST_F(Phase4NetworkingTest, E4_2_ValidSingleByteRequestReceivesPositiveResponse) {
    gw::XorCryptoStrategy reqCrypto(gw::GW_KEY_REQUEST);
    gw::XorCryptoStrategy respCrypto(gw::GW_KEY_RESPONSE);
    gw::Crc8Calculator crcCalc;
    gw::RequestBuilder builder(reqCrypto, crcCalc);
    gw::ResponseParser parser(respCrypto, crcCalc);

    gw::TcpClient client;
    client.connect("127.0.0.1", TEST_PORT);
    EXPECT_TRUE(client.isConnected());

    std::vector<uint8_t> frame = builder.build(gw::GW_ADDR_NODE_PRIMARY, gw::GW_ADDR_GW_PRIMARY, {0x12});
    client.sendFrame(frame);

    std::vector<uint8_t> respBytes = client.receiveFrame();
    gw::ClientResponse resp = parser.parse(respBytes);

    EXPECT_EQ(resp.type, gw::ResponseType::Positive);
    EXPECT_EQ(resp.failureCode, gw::FailureCode::None);
    ASSERT_EQ(resp.decryptedPayload.size(), 1u);
    EXPECT_EQ(resp.decryptedPayload[0], 0x21); // Nibble swap of 0x12 is 0x21
}

TEST_F(Phase4NetworkingTest, E4_3_InvalidSourceAddressReceivesNegativeResponse0x01) {
    gw::XorCryptoStrategy reqCrypto(gw::GW_KEY_REQUEST);
    gw::XorCryptoStrategy respCrypto(gw::GW_KEY_RESPONSE);
    gw::Crc8Calculator crcCalc;
    gw::RequestBuilder builder(reqCrypto, crcCalc);
    gw::ResponseParser parser(respCrypto, crcCalc);

    gw::TcpClient client;
    client.connect("127.0.0.1", TEST_PORT);

    // Invalid SA: 0xFFFF
    std::vector<uint8_t> frame = builder.build(0xFFFF, gw::GW_ADDR_GW_PRIMARY, {0x12});
    client.sendFrame(frame);

    std::vector<uint8_t> respBytes = client.receiveFrame();
    gw::ClientResponse resp = parser.parse(respBytes);

    EXPECT_EQ(resp.type, gw::ResponseType::Negative);
    EXPECT_EQ(resp.failureCode, gw::FailureCode::SourceAddrInvalid);
    EXPECT_TRUE(resp.decryptedPayload.empty());
}

TEST_F(Phase4NetworkingTest, E4_4_InvalidTargetAddressReceivesNegativeResponse0x02) {
    gw::XorCryptoStrategy reqCrypto(gw::GW_KEY_REQUEST);
    gw::XorCryptoStrategy respCrypto(gw::GW_KEY_RESPONSE);
    gw::Crc8Calculator crcCalc;
    gw::RequestBuilder builder(reqCrypto, crcCalc);
    gw::ResponseParser parser(respCrypto, crcCalc);

    gw::TcpClient client;
    client.connect("127.0.0.1", TEST_PORT);

    // Invalid TA: 0x9999
    std::vector<uint8_t> frame = builder.build(gw::GW_ADDR_NODE_PRIMARY, 0x9999, {0x12});
    client.sendFrame(frame);

    std::vector<uint8_t> respBytes = client.receiveFrame();
    gw::ClientResponse resp = parser.parse(respBytes);

    EXPECT_EQ(resp.type, gw::ResponseType::Negative);
    EXPECT_EQ(resp.failureCode, gw::FailureCode::TargetAddrInvalid);
    EXPECT_TRUE(resp.decryptedPayload.empty());
}

TEST_F(Phase4NetworkingTest, E4_5_CorruptedCrcReceivesNegativeResponse0x04) {
    gw::XorCryptoStrategy reqCrypto(gw::GW_KEY_REQUEST);
    gw::XorCryptoStrategy respCrypto(gw::GW_KEY_RESPONSE);
    gw::Crc8Calculator crcCalc;
    gw::RequestBuilder builder(reqCrypto, crcCalc);
    gw::ResponseParser parser(respCrypto, crcCalc);

    gw::TcpClient client;
    client.connect("127.0.0.1", TEST_PORT);

    // Corrupted CRC
    std::vector<uint8_t> frame = builder.buildInvalid(gw::GW_ADDR_NODE_PRIMARY,
                                                      gw::GW_ADDR_GW_PRIMARY,
                                                      {0x12},
                                                      true, false);
    client.sendFrame(frame);

    std::vector<uint8_t> respBytes = client.receiveFrame();
    gw::ClientResponse resp = parser.parse(respBytes);

    EXPECT_EQ(resp.type, gw::ResponseType::Negative);
    EXPECT_EQ(resp.failureCode, gw::FailureCode::IntegrityFailure);
    EXPECT_TRUE(resp.decryptedPayload.empty());
}

TEST_F(Phase4NetworkingTest, E4_6_MismatchedLengthReceivesNegativeResponse0x08) {
    gw::XorCryptoStrategy respCrypto(gw::GW_KEY_RESPONSE);
    gw::Crc8Calculator crcCalc;
    gw::ResponseParser parser(respCrypto, crcCalc);

    gw::TcpClient client;
    client.connect("127.0.0.1", TEST_PORT);

    // Mismatched length: Length field = 1 (< 2 bytes minimum)
    std::vector<uint8_t> frame = {
        0x0E, 0x80,             // SA: 0x0E80
        0x31, 0x08,             // TA: 0x3108
        0x00, 0x00, 0x00, 0x01, // Length: 1 (invalid)
        0xB8                    // 1 body byte
    };
    client.sendFrame(frame);

    std::vector<uint8_t> respBytes = client.receiveFrame();
    gw::ClientResponse resp = parser.parse(respBytes);

    EXPECT_EQ(resp.type, gw::ResponseType::Negative);
    EXPECT_EQ(resp.failureCode, gw::FailureCode::LengthMismatch);
    EXPECT_TRUE(resp.decryptedPayload.empty());
}

TEST_F(Phase4NetworkingTest, E4_7_TwoConcurrentClientsExchangeResponsesSimultaneously) {
    gw::XorCryptoStrategy reqCrypto(gw::GW_KEY_REQUEST);
    gw::XorCryptoStrategy respCrypto(gw::GW_KEY_RESPONSE);
    gw::Crc8Calculator crcCalc;

    std::atomic<bool> client1Ok{false};
    std::atomic<bool> client2Ok{false};

    std::thread t1([&]() {
        try {
            gw::TcpClient client;
            gw::RequestBuilder builder(reqCrypto, crcCalc);
            gw::ResponseParser parser(respCrypto, crcCalc);

            client.connect("127.0.0.1", TEST_PORT);
            std::vector<uint8_t> frame = builder.build(gw::GW_ADDR_NODE_PRIMARY, gw::GW_ADDR_GW_PRIMARY, {0x12});
            client.sendFrame(frame);
            std::vector<uint8_t> resp = client.receiveFrame();
            gw::ClientResponse parsed = parser.parse(resp);
            if (parsed.type == gw::ResponseType::Positive &&
                parsed.decryptedPayload.size() == 1 &&
                parsed.decryptedPayload[0] == 0x21) {
                client1Ok.store(true);
            }
        } catch (...) {}
    });

    std::thread t2([&]() {
        try {
            gw::TcpClient client;
            gw::RequestBuilder builder(reqCrypto, crcCalc);
            gw::ResponseParser parser(respCrypto, crcCalc);

            client.connect("127.0.0.1", TEST_PORT);
            std::vector<uint8_t> frame = builder.build(gw::GW_ADDR_NODE_SECONDARY, gw::GW_ADDR_GW_SECONDARY, {0x34});
            client.sendFrame(frame);
            std::vector<uint8_t> resp = client.receiveFrame();
            gw::ClientResponse parsed = parser.parse(resp);
            if (parsed.type == gw::ResponseType::Positive &&
                parsed.decryptedPayload.size() == 1 &&
                parsed.decryptedPayload[0] == 0x43) { // 0x34 nibble swap is 0x43
                client2Ok.store(true);
            }
        } catch (...) {}
    });

    t1.join();
    t2.join();

    EXPECT_TRUE(client1Ok.load());
    EXPECT_TRUE(client2Ok.load());
}

TEST_F(Phase4NetworkingTest, E4_8_ServerDoesNotCrashOnAbruptDisconnect) {
    gw::TcpClient client;
    client.connect("127.0.0.1", TEST_PORT);
    EXPECT_TRUE(client.isConnected());
    client.disconnect();

    std::this_thread::sleep_for(std::chrono::milliseconds(50));
    EXPECT_TRUE(server_->isRunning());

    gw::TcpClient nextClient;
    nextClient.connect("127.0.0.1", TEST_PORT);
    EXPECT_TRUE(nextClient.isConnected());
    nextClient.disconnect();
}

TEST_F(Phase4NetworkingTest, E4_10_ServerMetricsShowsNonZeroCounters) {
    gw::XorCryptoStrategy reqCrypto(gw::GW_KEY_REQUEST);
    gw::Crc8Calculator crcCalc;
    gw::RequestBuilder builder(reqCrypto, crcCalc);

    // Send at least one valid and one invalid request to populate metrics
    gw::TcpClient client;
    client.connect("127.0.0.1", TEST_PORT);
    std::vector<uint8_t> validReq = builder.build(gw::GW_ADDR_NODE_PRIMARY, gw::GW_ADDR_GW_PRIMARY, {0x12});
    client.sendFrame(validReq);
    (void)client.receiveFrame();

    std::vector<uint8_t> invalidReq = builder.build(0xFFFF, gw::GW_ADDR_GW_PRIMARY, {0x12});
    client.sendFrame(invalidReq);
    (void)client.receiveFrame();

    client.disconnect();

    gw::ServerMetrics& metrics = gw::ServerMetrics::instance();
    EXPECT_GT(metrics.totalRequests(), 0u);
    EXPECT_GT(metrics.positiveResponses(), 0u);
    EXPECT_GT(metrics.totalConnections(), 0u);
    EXPECT_GT(metrics.negativeCount(gw::FailureCode::SourceAddrInvalid) +
              metrics.negativeCount(gw::FailureCode::TargetAddrInvalid) +
              metrics.negativeCount(gw::FailureCode::IntegrityFailure) +
              metrics.negativeCount(gw::FailureCode::LengthMismatch), 0u);

    // Verify dump executes without throwing
    metrics.dump();
}

} // namespace
