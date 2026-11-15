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
#include <atomic>

namespace {

constexpr uint16_t STRESS_PORT = 13450;
constexpr int NUM_CLIENTS = 32;
constexpr int REQUESTS_PER_CLIENT = 1000;

class ConcurrentClientsTest : public ::testing::Test {
protected:
    static void SetUpTestSuite() {
        gw::PlatformSocket::initializePlatform();
        gw::ServerMetrics::instance().reset();

        serverThread_ = std::thread([]() {
            server_ = new gw::GatewayServer(STRESS_PORT);
            server_->start();
        });
        std::this_thread::sleep_for(std::chrono::milliseconds(300));
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

std::thread ConcurrentClientsTest::serverThread_;
gw::GatewayServer* ConcurrentClientsTest::server_ = nullptr;

TEST_F(ConcurrentClientsTest, ThirtyTwoConcurrentClients_ZeroDrop) {
    gw::XorCryptoStrategy reqCrypto(gw::GW_KEY_REQUEST);
    gw::XorCryptoStrategy respCrypto(gw::GW_KEY_RESPONSE);
    gw::Crc8Calculator crcCalc;

    std::vector<std::thread> clientThreads;
    std::atomic<uint64_t> totalSent{0};
    std::atomic<uint64_t> totalReceived{0};
    std::atomic<int> failedClients{0};

    for (int clientId = 0; clientId < NUM_CLIENTS; ++clientId) {
        clientThreads.emplace_back([&, clientId]() {
            try {
                gw::TcpClient client;
                client.connect("127.0.0.1", STRESS_PORT);

                gw::RequestBuilder builder(reqCrypto, crcCalc);
                gw::ResponseParser parser(respCrypto, crcCalc);

                uint64_t clientSent = 0;
                uint64_t clientRecv = 0;

                for (int req = 0; req < REQUESTS_PER_CLIENT; ++req) {
                    std::vector<uint8_t> frame;
                    bool expectPositive = true;

                    int pattern = req % 5;
                    switch (pattern) {
                        case 0:
                            // Valid request (0x12 -> 0x21)
                            frame = builder.build(gw::GW_ADDR_NODE_PRIMARY, gw::GW_ADDR_GW_PRIMARY, {0x12});
                            break;
                        case 1:
                            // Invalid SA (0xFFFF -> 0x01)
                            frame = builder.build(0xFFFF, gw::GW_ADDR_GW_PRIMARY, {0x12});
                            expectPositive = false;
                            break;
                        case 2:
                            // Invalid TA (0x9999 -> 0x02)
                            frame = builder.build(gw::GW_ADDR_NODE_PRIMARY, 0x9999, {0x12});
                            expectPositive = false;
                            break;
                        case 3:
                            // Bad CRC (0x04)
                            frame = builder.buildInvalid(gw::GW_ADDR_NODE_PRIMARY, gw::GW_ADDR_GW_PRIMARY, {0x12}, true, false);
                            expectPositive = false;
                            break;
                        case 4:
                            // Mismatched length (0x08)
                            frame = {0x0E, 0x80, 0x31, 0x08, 0x00, 0x00, 0x00, 0x01, 0xB8};
                            expectPositive = false;
                            break;
                    }

                    client.sendFrame(frame);
                    ++clientSent;

                    std::vector<uint8_t> respBytes = client.receiveFrame();
                    if (!respBytes.empty()) {
                        ++clientRecv;
                        gw::ClientResponse resp = parser.parse(respBytes);
                        if (expectPositive) {
                            if (resp.type != gw::ResponseType::Positive || resp.decryptedPayload[0] != 0x21) {
                                ++failedClients;
                            }
                        } else {
                            if (resp.type != gw::ResponseType::Negative) {
                                ++failedClients;
                            }
                        }
                    }
                }

                totalSent.fetch_add(clientSent, std::memory_order_relaxed);
                totalReceived.fetch_add(clientRecv, std::memory_order_relaxed);

                if (clientSent != clientRecv || clientRecv != REQUESTS_PER_CLIENT) {
                    ++failedClients;
                }
                client.disconnect();
            } catch (...) {
                ++failedClients;
            }
        });
    }

    for (auto& th : clientThreads) {
        th.join();
    }

    // Exit condition E6.5: Zero-drop under 32 concurrent clients (32,000 requests -> 32,000 responses)
    EXPECT_EQ(totalSent.load(), static_cast<uint64_t>(NUM_CLIENTS * REQUESTS_PER_CLIENT));
    EXPECT_EQ(totalReceived.load(), static_cast<uint64_t>(NUM_CLIENTS * REQUESTS_PER_CLIENT));
    EXPECT_EQ(totalSent.load(), totalReceived.load());
    EXPECT_EQ(failedClients.load(), 0);

    // Exit condition E6.6: No request skipped
    EXPECT_EQ(totalReceived.load(), 32000u);

    // Exit condition E6.9: ServerMetrics::dump() after stress test shows:
    // totalRequests == 32000, sum of positive and negative responses == 32000
    gw::ServerMetrics& metrics = gw::ServerMetrics::instance();
    EXPECT_EQ(metrics.totalRequests(), 32000u);
    uint64_t sumResponses = metrics.positiveResponses() +
                           metrics.negativeCount(gw::FailureCode::SourceAddrInvalid) +
                           metrics.negativeCount(gw::FailureCode::TargetAddrInvalid) +
                           metrics.negativeCount(gw::FailureCode::IntegrityFailure) +
                           metrics.negativeCount(gw::FailureCode::LengthMismatch);
    EXPECT_EQ(sumResponses, 32000u);
    metrics.dump();
}

} // namespace
