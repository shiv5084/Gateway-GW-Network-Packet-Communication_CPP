#include <gtest/gtest.h>
#include "tcp_server.hpp"
#include "gateway_server.hpp"
#include "connection_handler.hpp"
#include "tcp_client.hpp"
#include "logger.hpp"
#include "server_metrics.hpp"
#include <type_traits>

namespace {

// Exit condition E4.11:
// Rule of Five verified for TcpServer, GatewayServer, ConnectionHandler, TcpClient:
// copy operations cause compile error;
// TcpServer/GatewayServer move operations cause compile error;
// ConnectionHandler/TcpClient move operations compile and transfer ownership correctly.

TEST(RuleOfFiveTraitsTest, TcpServerTraits) {
    EXPECT_FALSE(std::is_copy_constructible<gw::TcpServer>::value);
    EXPECT_FALSE(std::is_copy_assignable<gw::TcpServer>::value);
    EXPECT_FALSE(std::is_move_constructible<gw::TcpServer>::value);
    EXPECT_FALSE(std::is_move_assignable<gw::TcpServer>::value);
}

TEST(RuleOfFiveTraitsTest, GatewayServerTraits) {
    EXPECT_FALSE(std::is_copy_constructible<gw::GatewayServer>::value);
    EXPECT_FALSE(std::is_copy_assignable<gw::GatewayServer>::value);
    EXPECT_FALSE(std::is_move_constructible<gw::GatewayServer>::value);
    EXPECT_FALSE(std::is_move_assignable<gw::GatewayServer>::value);
}

TEST(RuleOfFiveTraitsTest, ConnectionHandlerTraits) {
    EXPECT_FALSE(std::is_copy_constructible<gw::ConnectionHandler>::value);
    EXPECT_FALSE(std::is_copy_assignable<gw::ConnectionHandler>::value);
    EXPECT_TRUE(std::is_move_constructible<gw::ConnectionHandler>::value);
    EXPECT_TRUE(std::is_move_assignable<gw::ConnectionHandler>::value);
}

TEST(RuleOfFiveTraitsTest, TcpClientTraits) {
    EXPECT_FALSE(std::is_copy_constructible<gw::TcpClient>::value);
    EXPECT_FALSE(std::is_copy_assignable<gw::TcpClient>::value);
    EXPECT_TRUE(std::is_move_constructible<gw::TcpClient>::value);
    EXPECT_TRUE(std::is_move_assignable<gw::TcpClient>::value);
}

// Exit condition E4.12:
// Rule of Five verified for singletons: Logger and ServerMetrics copy AND move operations all deleted
TEST(RuleOfFiveTraitsTest, SingletonsTraits) {
    EXPECT_FALSE(std::is_copy_constructible<gw::Logger>::value);
    EXPECT_FALSE(std::is_copy_assignable<gw::Logger>::value);
    EXPECT_FALSE(std::is_move_constructible<gw::Logger>::value);
    EXPECT_FALSE(std::is_move_assignable<gw::Logger>::value);

    EXPECT_FALSE(std::is_copy_constructible<gw::ServerMetrics>::value);
    EXPECT_FALSE(std::is_copy_assignable<gw::ServerMetrics>::value);
    EXPECT_FALSE(std::is_move_constructible<gw::ServerMetrics>::value);
    EXPECT_FALSE(std::is_move_assignable<gw::ServerMetrics>::value);
}

} // namespace
