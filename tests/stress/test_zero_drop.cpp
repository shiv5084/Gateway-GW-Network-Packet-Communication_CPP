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
#include <atomic>

namespace {

constexpr uint16_t ZERO_DROP_PORT = 13460;
constexpr int CONCURRENT_THREADS = 16;
constexpr int REQUESTS_PER_THREAD = 200;

class ZeroDropTest : public ::testing::Test {
protected:
    static void SetUpTestSuite() {
        gw::PlatformSocket::initializePlatform();
        serverThread_ = std::thread([]() {
            server_ = new gw::GatewayServer(ZERO_DROP_PORT);
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
};

std::thread ZeroDropTest::serverThread_;
gw::GatewayServer* ZeroDropTest::server_ = nullptr;

TEST_F(ZeroDropTest, TotalSentEqualsTotalReceivedPerThread) {
    gw::XorCryptoStrategy reqCrypto(gw::GW_KEY_REQUEST);
    gw::XorCryptoStrategy respCrypto(gw::GW_KEY_RESPONSE);
    gw::Crc8Calculator crcCalc;

    std::vector<std::thread> threads;
    std::vector<uint64_t> sentPerThread(CONCURRENT_THREADS, 0);
    std::vector<uint64_t> recvPerThread(CONCURRENT_THREADS, 0);

    for (int t = 0; t < CONCURRENT_THREADS; ++t) {
        threads.emplace_back([&, t]() {
            try {
                gw::TcpClient client;
                client.connect("127.0.0.1", ZERO_DROP_PORT);

                gw::RequestBuilder builder(reqCrypto, crcCalc);
                gw::ResponseParser parser(respCrypto, crcCalc);

                for (int req = 0; req < REQUESTS_PER_THREAD; ++req) {
                    std::vector<uint8_t> frame = builder.build(gw::GW_ADDR_NODE_PRIMARY,
                                                              gw::GW_ADDR_GW_PRIMARY,
                                                              {static_cast<uint8_t>(req & 0xFF)});
                    client.sendFrame(frame);
                    ++sentPerThread[t];

                    std::vector<uint8_t> resp = client.receiveFrame();
                    if (!resp.empty()) {
                        ++recvPerThread[t];
                    }
                }
                client.disconnect();
            } catch (...) {}
        });
    }

    for (auto& th : threads) {
        th.join();
    }

    // Assert that every single thread experienced ZERO dropped packets
    for (int t = 0; t < CONCURRENT_THREADS; ++t) {
        EXPECT_EQ(sentPerThread[t], static_cast<uint64_t>(REQUESTS_PER_THREAD))
            << "Thread " << t << " failed to send all requests";
        EXPECT_EQ(recvPerThread[t], static_cast<uint64_t>(REQUESTS_PER_THREAD))
            << "Thread " << t << " experienced dropped responses";
        EXPECT_EQ(sentPerThread[t], recvPerThread[t])
            << "Thread " << t << " send/receive count mismatch";
    }
}

} // namespace
