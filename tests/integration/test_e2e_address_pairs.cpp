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

constexpr uint16_t ADDR_TEST_PORT = 13435;

class E2EAddressPairsTest : public ::testing::Test {
protected:
    static void SetUpTestSuite() {
        gw::PlatformSocket::initializePlatform();
        serverThread_ = std::thread([]() {
            server_ = new gw::GatewayServer(ADDR_TEST_PORT);
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

std::thread E2EAddressPairsTest::serverThread_;
gw::GatewayServer* E2EAddressPairsTest::server_ = nullptr;

TEST_F(E2EAddressPairsTest, AllAddressPairPermutations) {
    struct AddressPair {
        uint16_t sa;
        uint16_t ta;
    };

    std::vector<AddressPair> pairs = {
        {gw::GW_ADDR_NODE_PRIMARY,   gw::GW_ADDR_GW_PRIMARY},   // 0x0E80 -> 0x3108
        {gw::GW_ADDR_NODE_PRIMARY,   gw::GW_ADDR_GW_SECONDARY}, // 0x0E80 -> 0x1380
        {gw::GW_ADDR_NODE_SECONDARY, gw::GW_ADDR_GW_PRIMARY},   // 0xE008 -> 0x3108
        {gw::GW_ADDR_NODE_SECONDARY, gw::GW_ADDR_GW_SECONDARY}  // 0xE008 -> 0x1380
    };

    gw::TcpClient client;
    client.connect("127.0.0.1", ADDR_TEST_PORT);

    for (const auto& pair : pairs) {
        std::vector<uint8_t> frame = builder_.build(pair.sa, pair.ta, {0x12});
        client.sendFrame(frame);

        std::vector<uint8_t> respBytes = client.receiveFrame();
        gw::ClientResponse resp = parser_.parse(respBytes);

        EXPECT_EQ(resp.type, gw::ResponseType::Positive);
        EXPECT_EQ(resp.sourceAddr, pair.ta) << "Response SA must equal request TA";
        EXPECT_EQ(resp.targetAddr, pair.sa) << "Response TA must equal request SA";
        ASSERT_EQ(resp.decryptedPayload.size(), 1u);
        EXPECT_EQ(resp.decryptedPayload[0], 0x21);
    }
}

} // namespace
