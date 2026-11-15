#include <gtest/gtest.h>
#include "gw_types.hpp"
#include "gw_config.hpp"
#include "platform_socket.hpp"
#include "socket_guard.hpp"
#include "logger.hpp"
#include <thread>
#include <vector>
#include <type_traits>
#include <sstream>

using namespace gw;

// ============================================================================
// E1.7: Configuration Constants Verification
// ============================================================================
TEST(ConfigTest, ConstantsMatchSpec) {
    EXPECT_EQ(DEFAULT_PORT, 13400);
    EXPECT_EQ(GW_KEY_REQUEST, 0xAA);
    EXPECT_EQ(GW_KEY_RESPONSE, 0x55);
    EXPECT_EQ(GW_CRC8_POLY, 0x07);
    EXPECT_EQ(GW_CRC8_INIT, 0x00);
    EXPECT_EQ(GW_HEADER_SIZE, 8u);
    EXPECT_EQ(GW_CRC_SIZE, 1u);
    EXPECT_EQ(GW_MIN_PACKET_SIZE, 9u);
    EXPECT_EQ(GW_NEGATIVE_RESP_SIZE, 10u);
    EXPECT_EQ(GW_MAX_PAYLOAD_SIZE, 65535u);
}

// ============================================================================
// E1.6: Protocol Types & Failure Codes Verification
// ============================================================================
TEST(TypesTest, FailureCodesMatchSpec) {
    EXPECT_EQ(static_cast<uint8_t>(FailureCode::None), 0x00);
    EXPECT_EQ(static_cast<uint8_t>(FailureCode::SourceAddrInvalid), 0x01);
    EXPECT_EQ(static_cast<uint8_t>(FailureCode::TargetAddrInvalid), 0x02);
    EXPECT_EQ(static_cast<uint8_t>(FailureCode::IntegrityFailure), 0x04);
    EXPECT_EQ(static_cast<uint8_t>(FailureCode::LengthMismatch), 0x08);

    // Verify string conversion
    EXPECT_STREQ(failureCodeToString(FailureCode::None), "None");
    EXPECT_STREQ(failureCodeToString(FailureCode::SourceAddrInvalid), "SourceAddrInvalid (0x01)");
    EXPECT_STREQ(failureCodeToString(FailureCode::TargetAddrInvalid), "TargetAddrInvalid (0x02)");
    EXPECT_STREQ(failureCodeToString(FailureCode::IntegrityFailure), "IntegrityFailure (0x04)");
    EXPECT_STREQ(failureCodeToString(FailureCode::LengthMismatch), "LengthMismatch (0x08)");
}

TEST(TypesTest, AddressValidation) {
    // Valid Source Addresses: 0x0E80 or 0xE008
    EXPECT_TRUE(isValidSourceAddress(0x0E80));
    EXPECT_TRUE(isValidSourceAddress(0xE008));
    EXPECT_FALSE(isValidSourceAddress(0x3108));
    EXPECT_FALSE(isValidSourceAddress(0x1380));
    EXPECT_FALSE(isValidSourceAddress(0x0000));
    EXPECT_FALSE(isValidSourceAddress(0xFFFF));

    // Valid Target Addresses: 0x3108 or 0x1380
    EXPECT_TRUE(isValidTargetAddress(0x3108));
    EXPECT_TRUE(isValidTargetAddress(0x1380));
    EXPECT_FALSE(isValidTargetAddress(0x0E80));
    EXPECT_FALSE(isValidTargetAddress(0xE008));
    EXPECT_FALSE(isValidTargetAddress(0x0000));
    EXPECT_FALSE(isValidTargetAddress(0x9999));
}

// ============================================================================
// E1.5 & E1.5a: SocketGuard RAII and Rule of Five Verification
// ============================================================================
TEST(SocketGuardTest, RuleOfFiveTypeTraits) {
    // Non-copyable
    EXPECT_FALSE(std::is_copy_constructible<SocketGuard>::value);
    EXPECT_FALSE(std::is_copy_assignable<SocketGuard>::value);

    // Movable
    EXPECT_TRUE(std::is_move_constructible<SocketGuard>::value);
    EXPECT_TRUE(std::is_move_assignable<SocketGuard>::value);
}

TEST(SocketGuardTest, MoveSemanticsTransferOwnership) {
    PlatformSocket::initializePlatform();

    // Create a real socket to test ownership lifecycle
#if defined(_WIN32)
    gw_socket_t rawSock = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
#else
    gw_socket_t rawSock = ::socket(AF_INET, SOCK_STREAM, 0);
#endif

    ASSERT_NE(rawSock, GW_INVALID_SOCKET);

    {
        SocketGuard guardA(rawSock);
        EXPECT_TRUE(guardA.isValid());
        EXPECT_EQ(guardA.get(), rawSock);

        // Move construct: guardB takes ownership, guardA invalidated
        SocketGuard guardB(std::move(guardA));
        EXPECT_FALSE(guardA.isValid());
        EXPECT_EQ(guardA.get(), GW_INVALID_SOCKET);
        EXPECT_TRUE(guardB.isValid());
        EXPECT_EQ(guardB.get(), rawSock);

        // Move assign: guardC takes ownership, guardB invalidated
        SocketGuard guardC;
        EXPECT_FALSE(guardC.isValid());
        guardC = std::move(guardB);
        EXPECT_FALSE(guardB.isValid());
        EXPECT_TRUE(guardC.isValid());
        EXPECT_EQ(guardC.get(), rawSock);

        // Reset manual close
        guardC.reset();
        EXPECT_FALSE(guardC.isValid());
    }

    PlatformSocket::cleanupPlatform();
}

TEST(SocketGuardTest, AutoClosesOnScopeExit) {
    PlatformSocket::initializePlatform();

#if defined(_WIN32)
    gw_socket_t rawSock = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
#else
    gw_socket_t rawSock = ::socket(AF_INET, SOCK_STREAM, 0);
#endif
    ASSERT_NE(rawSock, GW_INVALID_SOCKET);

    {
        SocketGuard guard(rawSock);
        EXPECT_TRUE(guard.isValid());
    } // guard goes out of scope here -> auto-closes rawSock

    // Verify rawSock is now closed by attempting an operation on it
    char buf[1];
#if defined(_WIN32)
    int res = ::recv(rawSock, buf, 1, 0);
    EXPECT_EQ(res, SOCKET_ERROR);
    int err = WSAGetLastError();
    EXPECT_TRUE(err == WSAENOTSOCK || err == WSAEBADF);
#else
    ssize_t res = ::recv(rawSock, buf, 1, 0);
    EXPECT_EQ(res, -1);
#endif

    PlatformSocket::cleanupPlatform();
}

// ============================================================================
// E1.4: Logger Singleton Concurrent Thread-Safety Verification
// ============================================================================
TEST(LoggerTest, SingletonRuleOfFiveTypeTraits) {
    EXPECT_FALSE(std::is_copy_constructible<Logger>::value);
    EXPECT_FALSE(std::is_copy_assignable<Logger>::value);
    EXPECT_FALSE(std::is_move_constructible<Logger>::value);
    EXPECT_FALSE(std::is_move_assignable<Logger>::value);
}

TEST(LoggerTest, MultiThreadedConcurrentLogging) {
    Logger& logger = Logger::instance();
    logger.setLevel(LogLevel::DEBUG);

    std::ostringstream captureStream;
    logger.setOutputStream(&captureStream);

    constexpr int kIterations = 50;
    std::thread t1([&]() {
        for (int i = 0; i < kIterations; ++i) {
            Logger::instance().log(LogLevel::INFO, "THRD1", "Concurrent message from thread 1");
        }
    });

    std::thread t2([&]() {
        for (int i = 0; i < kIterations; ++i) {
            uint8_t dummyData[] = {0x0E, 0x80, 0x31, 0x08};
            Logger::instance().hexDump(LogLevel::DEBUG, "THRD2", "DUMP", dummyData, sizeof(dummyData));
        }
    });

    t1.join();
    t2.join();

    // Reset stream back to std::cout
    logger.setOutputStream(nullptr);

    std::string captured = captureStream.str();
    EXPECT_FALSE(captured.empty());
    EXPECT_NE(captured.find("THRD1"), std::string::npos);
    EXPECT_NE(captured.find("THRD2"), std::string::npos);
}

// ============================================================================
// PlatformSocket Adapter Verification
// ============================================================================
TEST(PlatformSocketTest, AdapterLifecycle) {
    EXPECT_TRUE(PlatformSocket::initializePlatform());

    PlatformSocket sock;
    EXPECT_FALSE(sock.isValid());

    uint8_t dummy = 0xFF;
    EXPECT_EQ(sock.send(&dummy, 1), -1);
    EXPECT_EQ(sock.recv(&dummy, 1), -1);

    PlatformSocket::cleanupPlatform();
}
