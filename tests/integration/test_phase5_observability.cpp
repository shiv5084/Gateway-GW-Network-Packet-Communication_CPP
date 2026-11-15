#include <gtest/gtest.h>
#include "gateway_server.hpp"
#include "tcp_client.hpp"
#include "request_builder.hpp"
#include "response_parser.hpp"
#include "xor_crypto_strategy.hpp"
#include "crc8_calculator.hpp"
#include "server_metrics.hpp"
#include "logger.hpp"
#include "gw_config.hpp"
#include "platform_socket.hpp"
#include <thread>
#include <chrono>
#include <sstream>
#include <string>
#include <vector>
#include <regex>

namespace {

constexpr uint16_t OBS_TEST_PORT = 13420;

class Phase5ObservabilityTest : public ::testing::Test {
protected:
    void SetUp() override {
        gw::PlatformSocket::initializePlatform();
        gw::ServerMetrics::instance().reset();
        gw::Logger::instance().setLevel(gw::LogLevel::DEBUG);
        logBuffer_.str("");
        logBuffer_.clear();
        gw::Logger::instance().setOutputStream(&logBuffer_);
    }

    void TearDown() override {
        gw::Logger::instance().setOutputStream(&std::cout);
        gw::Logger::instance().setLevel(gw::LogLevel::INFO);
    }

    std::ostringstream logBuffer_;
};

TEST_F(Phase5ObservabilityTest, E5_1_AllSixLogLineCategoriesProducedForValidRequest) {
    gw::GatewayServer server(OBS_TEST_PORT);
    std::thread serverThread([&]() { server.start(); });
    std::this_thread::sleep_for(std::chrono::milliseconds(200));

    gw::XorCryptoStrategy reqCrypto(gw::GW_KEY_REQUEST);
    gw::XorCryptoStrategy respCrypto(gw::GW_KEY_RESPONSE);
    gw::Crc8Calculator crcCalc;
    gw::RequestBuilder builder(reqCrypto, crcCalc);
    gw::ResponseParser parser(respCrypto, crcCalc);

    gw::TcpClient client;
    client.connect("127.0.0.1", OBS_TEST_PORT);
    std::vector<uint8_t> frame = builder.build(gw::GW_ADDR_NODE_PRIMARY, gw::GW_ADDR_GW_PRIMARY, {0x12});
    client.sendFrame(frame);
    std::vector<uint8_t> resp = client.receiveFrame();
    client.disconnect();

    server.stop();
    serverThread.join();

    std::string logs = logBuffer_.str();

    // 1. Connection event
    EXPECT_TRUE(logs.find("Client connected from") != std::string::npos);

    // 2. RX hex dump
    EXPECT_TRUE(logs.find("[FRAMER] RX: 0E 80 31 08 00 00 00 02 B8 21") != std::string::npos);

    // 3. Validation result
    EXPECT_TRUE(logs.find("[VALID ] Validation passed") != std::string::npos);

    // 4. Transformation trace
    EXPECT_TRUE(logs.find("[TRANS ] Decrypt: [12] \xe2\x86\x92 Swap: [21] \xe2\x86\x92 Encrypt: [74] \xe2\x86\x92 CRC: [4B]") != std::string::npos);

    // 5. TX hex dump
    EXPECT_TRUE(logs.find("[FRAMER] TX: 31 08 0E 80 00 00 00 02 74 4B") != std::string::npos);

    // 6. Response delivery confirmation
    EXPECT_TRUE(logs.find("Response delivered (10 bytes)") != std::string::npos);
}

TEST_F(Phase5ObservabilityTest, E5_2_TransformationTraceMatchesExactFormat) {
    gw::GatewayServer server(OBS_TEST_PORT + 1);
    std::thread serverThread([&]() { server.start(); });
    std::this_thread::sleep_for(std::chrono::milliseconds(200));

    gw::XorCryptoStrategy reqCrypto(gw::GW_KEY_REQUEST);
    gw::Crc8Calculator crcCalc;
    gw::RequestBuilder builder(reqCrypto, crcCalc);

    gw::TcpClient client;
    client.connect("127.0.0.1", OBS_TEST_PORT + 1);
    std::vector<uint8_t> frame = builder.build(gw::GW_ADDR_NODE_PRIMARY, gw::GW_ADDR_GW_PRIMARY, {0x12});
    client.sendFrame(frame);
    (void)client.receiveFrame();
    client.disconnect();

    server.stop();
    serverThread.join();

    std::string logs = logBuffer_.str();
    std::string expectedTrace = "Decrypt: [12] \xe2\x86\x92 Swap: [21] \xe2\x86\x92 Encrypt: [74] \xe2\x86\x92 CRC: [4B]";
    EXPECT_TRUE(logs.find(expectedTrace) != std::string::npos);
}

TEST_F(Phase5ObservabilityTest, E5_3_HexDumpsRxAndTxExactBytes) {
    gw::GatewayServer server(OBS_TEST_PORT + 2);
    std::thread serverThread([&]() { server.start(); });
    std::this_thread::sleep_for(std::chrono::milliseconds(200));

    gw::XorCryptoStrategy reqCrypto(gw::GW_KEY_REQUEST);
    gw::Crc8Calculator crcCalc;
    gw::RequestBuilder builder(reqCrypto, crcCalc);

    gw::TcpClient client;
    client.connect("127.0.0.1", OBS_TEST_PORT + 2);
    std::vector<uint8_t> frame = builder.build(gw::GW_ADDR_NODE_PRIMARY, gw::GW_ADDR_GW_PRIMARY, {0x12});
    client.sendFrame(frame);
    (void)client.receiveFrame();
    client.disconnect();

    server.stop();
    serverThread.join();

    std::string logs = logBuffer_.str();
    EXPECT_TRUE(logs.find("0E 80 31 08 00 00 00 02 B8 21") != std::string::npos);
    EXPECT_TRUE(logs.find("31 08 0E 80 00 00 00 02 74 4B") != std::string::npos);
}

TEST_F(Phase5ObservabilityTest, E5_4_ValidationFailureLogsSpecificFailureCodeName) {
    gw::GatewayServer server(OBS_TEST_PORT + 3);
    std::thread serverThread([&]() { server.start(); });
    std::this_thread::sleep_for(std::chrono::milliseconds(200));

    gw::XorCryptoStrategy reqCrypto(gw::GW_KEY_REQUEST);
    gw::Crc8Calculator crcCalc;
    gw::RequestBuilder builder(reqCrypto, crcCalc);

    gw::TcpClient client;
    client.connect("127.0.0.1", OBS_TEST_PORT + 3);

    // Invalid SA (0xFFFF)
    std::vector<uint8_t> frame = builder.build(0xFFFF, gw::GW_ADDR_GW_PRIMARY, {0x12});
    client.sendFrame(frame);
    (void)client.receiveFrame();
    client.disconnect();

    server.stop();
    serverThread.join();

    std::string logs = logBuffer_.str();
    EXPECT_TRUE(logs.find("Validation failed: SourceAddrInvalid (0x01)") != std::string::npos);
}

TEST_F(Phase5ObservabilityTest, E5_5_ServerMetricsDumpShowsAccurateCounters) {
    gw::GatewayServer server(OBS_TEST_PORT + 4);
    std::thread serverThread([&]() { server.start(); });
    std::this_thread::sleep_for(std::chrono::milliseconds(200));

    gw::XorCryptoStrategy reqCrypto(gw::GW_KEY_REQUEST);
    gw::Crc8Calculator crcCalc;
    gw::RequestBuilder builder(reqCrypto, crcCalc);

    gw::TcpClient client;
    client.connect("127.0.0.1", OBS_TEST_PORT + 4);
    // Send 2 valid requests
    client.sendFrame(builder.build(gw::GW_ADDR_NODE_PRIMARY, gw::GW_ADDR_GW_PRIMARY, {0x12}));
    (void)client.receiveFrame();
    client.sendFrame(builder.build(gw::GW_ADDR_NODE_SECONDARY, gw::GW_ADDR_GW_SECONDARY, {0x34}));
    (void)client.receiveFrame();

    // Send 1 invalid request (bad SA)
    client.sendFrame(builder.build(0xFFFF, gw::GW_ADDR_GW_PRIMARY, {0x12}));
    (void)client.receiveFrame();
    client.disconnect();

    server.stop();
    serverThread.join();

    gw::ServerMetrics::instance().dump();
    std::string logs = logBuffer_.str();

    EXPECT_TRUE(logs.find("Total Requests:       3") != std::string::npos);
    EXPECT_TRUE(logs.find("Positive Responses:   2") != std::string::npos);
    EXPECT_TRUE(logs.find("Negative (0x01 SA):   1") != std::string::npos);
}

TEST_F(Phase5ObservabilityTest, E5_6_LogLevelFilteringSuppressesLowerLevels) {
    // Test INFO level: suppresses DEBUG
    gw::Logger::instance().setLevel(gw::LogLevel::INFO);
    gw::Logger::instance().log(gw::LogLevel::DEBUG, "TEST", "Debug message should be suppressed");
    gw::Logger::instance().log(gw::LogLevel::INFO, "TEST", "Info message should appear");
    gw::Logger::instance().log(gw::LogLevel::WARN, "TEST", "Warn message should appear");
    gw::Logger::instance().log(gw::LogLevel::ERROR, "TEST", "Error message should appear");

    std::string infoLogs = logBuffer_.str();
    EXPECT_EQ(infoLogs.find("Debug message should be suppressed"), std::string::npos);
    EXPECT_TRUE(infoLogs.find("Info message should appear") != std::string::npos);
    EXPECT_TRUE(infoLogs.find("Warn message should appear") != std::string::npos);
    EXPECT_TRUE(infoLogs.find("Error message should appear") != std::string::npos);

    // Test ERROR level: suppresses DEBUG, INFO, WARN
    logBuffer_.str("");
    logBuffer_.clear();
    gw::Logger::instance().setLevel(gw::LogLevel::ERROR);
    gw::Logger::instance().log(gw::LogLevel::DEBUG, "TEST", "Debug suppressed");
    gw::Logger::instance().log(gw::LogLevel::INFO, "TEST", "Info suppressed");
    gw::Logger::instance().log(gw::LogLevel::WARN, "TEST", "Warn suppressed");
    gw::Logger::instance().log(gw::LogLevel::ERROR, "TEST", "Error appeared");

    std::string errorLogs = logBuffer_.str();
    EXPECT_EQ(errorLogs.find("Debug suppressed"), std::string::npos);
    EXPECT_EQ(errorLogs.find("Info suppressed"), std::string::npos);
    EXPECT_EQ(errorLogs.find("Warn suppressed"), std::string::npos);
    EXPECT_TRUE(errorLogs.find("Error appeared") != std::string::npos);
}

TEST_F(Phase5ObservabilityTest, E5_7_ThreadSafeLoggingNoGarbledLinesUnderConcurrency) {
    gw::Logger::instance().setLevel(gw::LogLevel::DEBUG);

    std::vector<std::thread> threads;
    constexpr int NUM_THREADS = 4;
    constexpr int MESSAGES_PER_THREAD = 50;

    for (int t = 0; t < NUM_THREADS; ++t) {
        threads.emplace_back([t]() {
            for (int m = 0; m < MESSAGES_PER_THREAD; ++m) {
                gw::Logger::instance().log(gw::LogLevel::INFO, "THRD" + std::to_string(t),
                    "Thread " + std::to_string(t) + " message " + std::to_string(m));
            }
        });
    }

    for (auto& th : threads) {
        th.join();
    }

    std::string logs = logBuffer_.str();
    std::istringstream stream(logs);
    std::string line;
    int lineCount = 0;

    // Verify each line matches: [YYYY-MM-DD HH:MM:SS.mmm] [LEVEL] [MODULE] message
    // regex: ^\[\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d{3}\] \[[A-Z ]{5}\] \[[A-Za-z0-9 ]{6}\] .*$
    std::regex logPattern(R"(\[\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d{3}\] \[[A-Z ]{5}\] \[[A-Za-z0-9 ]{6}\] .*)");

    while (std::getline(stream, line)) {
        if (line.empty()) continue;
        EXPECT_TRUE(std::regex_match(line, logPattern)) << "Garbled line: " << line;
        ++lineCount;
    }

    EXPECT_EQ(lineCount, NUM_THREADS * MESSAGES_PER_THREAD);
}

} // namespace
