#include <gtest/gtest.h>
#include "tcp_client.hpp"

namespace {

TEST(TcpClientTest, InitialStateIsDisconnected) {
    gw::TcpClient client;
    EXPECT_FALSE(client.isConnected());
    EXPECT_EQ(client.getPeerPort(), 0);
    EXPECT_TRUE(client.getPeerIp().empty());
}

TEST(TcpClientTest, SendFrameThrowsWhenNotConnected) {
    gw::TcpClient client;
    std::vector<uint8_t> dummy = {0x01, 0x02};
    EXPECT_THROW(client.sendFrame(dummy), std::runtime_error);
}

TEST(TcpClientTest, ReceiveFrameThrowsWhenNotConnected) {
    gw::TcpClient client;
    EXPECT_THROW(client.receiveFrame(), std::runtime_error);
}

TEST(TcpClientTest, MoveSemanticsTransferState) {
    gw::TcpClient client1;
    gw::TcpClient client2(std::move(client1));
    EXPECT_FALSE(client2.isConnected());
}

} // namespace
