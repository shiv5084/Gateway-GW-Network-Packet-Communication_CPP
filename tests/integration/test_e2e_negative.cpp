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

constexpr uint16_t NEG_TEST_PORT = 13440;

class E2ENegativeTest : public ::testing::Test {
protected:
    static void SetUpTestSuite() {
        gw::PlatformSocket::initializePlatform();
        serverThread_ = std::thread([]() {
            server_ = new gw::GatewayServer(NEG_TEST_PORT);
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

std::thread E2ENegativeTest::serverThread_;
gw::GatewayServer* E2ENegativeTest::server_ = nullptr;

// Task P6.5: Invalid SA
TEST_F(E2ENegativeTest, InvalidSourceAddressReturns0x01) {
    gw::TcpClient client;
    client.connect("127.0.0.1", NEG_TEST_PORT);

    std::vector<uint8_t> frame = builder_.build(0xFFFF, gw::GW_ADDR_GW_PRIMARY, {0x12});
    client.sendFrame(frame);

    gw::ClientResponse resp = parser_.parse(client.receiveFrame());
    EXPECT_EQ(resp.type, gw::ResponseType::Negative);
    EXPECT_EQ(resp.failureCode, gw::FailureCode::SourceAddrInvalid);
    EXPECT_EQ(resp.sourceAddr, gw::GW_ADDR_GW_PRIMARY);
    EXPECT_EQ(resp.targetAddr, 0xFFFF);
}

// Task P6.6: Invalid TA
TEST_F(E2ENegativeTest, InvalidTargetAddressReturns0x02) {
    gw::TcpClient client;
    client.connect("127.0.0.1", NEG_TEST_PORT);

    std::vector<uint8_t> frame = builder_.build(gw::GW_ADDR_NODE_PRIMARY, 0x9999, {0x12});
    client.sendFrame(frame);

    gw::ClientResponse resp = parser_.parse(client.receiveFrame());
    EXPECT_EQ(resp.type, gw::ResponseType::Negative);
    EXPECT_EQ(resp.failureCode, gw::FailureCode::TargetAddrInvalid);
    EXPECT_EQ(resp.sourceAddr, 0x9999);
    EXPECT_EQ(resp.targetAddr, gw::GW_ADDR_NODE_PRIMARY);
}

// Task P6.7: Corrupted CRC
TEST_F(E2ENegativeTest, CorruptedCrcReturns0x04) {
    gw::TcpClient client;
    client.connect("127.0.0.1", NEG_TEST_PORT);

    std::vector<uint8_t> frame = builder_.buildInvalid(gw::GW_ADDR_NODE_PRIMARY,
                                                      gw::GW_ADDR_GW_PRIMARY,
                                                      {0x12},
                                                      true, false);
    client.sendFrame(frame);

    gw::ClientResponse resp = parser_.parse(client.receiveFrame());
    EXPECT_EQ(resp.type, gw::ResponseType::Negative);
    EXPECT_EQ(resp.failureCode, gw::FailureCode::IntegrityFailure);
}

// Task P6.8: Length mismatch
TEST_F(E2ENegativeTest, LengthMismatchReturns0x08) {
    gw::TcpClient client;
    client.connect("127.0.0.1", NEG_TEST_PORT);

    // Header says length 1 (invalid, minimum payload + CRC length is 2)
    std::vector<uint8_t> frame = {
        0x0E, 0x80,             // SA: 0x0E80
        0x31, 0x08,             // TA: 0x3108
        0x00, 0x00, 0x00, 0x01, // Length: 1
        0xB8                    // 1 body byte
    };
    client.sendFrame(frame);

    gw::ClientResponse resp = parser_.parse(client.receiveFrame());
    EXPECT_EQ(resp.type, gw::ResponseType::Negative);
    EXPECT_EQ(resp.failureCode, gw::FailureCode::LengthMismatch);
}

// Task P6.9: Validation Precedence (bad SA + bad CRC -> returns 0x01, not 0x04)
TEST_F(E2ENegativeTest, PrecedenceBadSaAndBadCrcReturns0x01) {
    gw::TcpClient client;
    client.connect("127.0.0.1", NEG_TEST_PORT);

    // Both SA invalid (0xFFFF) and CRC corrupted (true)
    std::vector<uint8_t> frame = builder_.buildInvalid(0xFFFF,
                                                      gw::GW_ADDR_GW_PRIMARY,
                                                      {0x12},
                                                      true, false);
    client.sendFrame(frame);

    gw::ClientResponse resp = parser_.parse(client.receiveFrame());
    EXPECT_EQ(resp.type, gw::ResponseType::Negative);
    EXPECT_EQ(resp.failureCode, gw::FailureCode::SourceAddrInvalid);
}

} // namespace
