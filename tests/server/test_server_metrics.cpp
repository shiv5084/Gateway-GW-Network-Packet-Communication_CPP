#include <gtest/gtest.h>
#include "server_metrics.hpp"
#include <type_traits>

namespace {

TEST(ServerMetricsTest, RuleOfFiveCompliance) {
    // E4.12: Rule of Five verified for singletons: copy AND move operations deleted
    EXPECT_FALSE(std::is_copy_constructible<gw::ServerMetrics>::value);
    EXPECT_FALSE(std::is_copy_assignable<gw::ServerMetrics>::value);
    EXPECT_FALSE(std::is_move_constructible<gw::ServerMetrics>::value);
    EXPECT_FALSE(std::is_move_assignable<gw::ServerMetrics>::value);
}

TEST(ServerMetricsTest, CountersIncrementCorrectly) {
    gw::ServerMetrics& metrics = gw::ServerMetrics::instance();
    metrics.reset();

    EXPECT_EQ(metrics.totalRequests(), 0u);
    EXPECT_EQ(metrics.positiveResponses(), 0u);
    EXPECT_EQ(metrics.activeConnections(), 0u);
    EXPECT_EQ(metrics.totalConnections(), 0u);

    metrics.onClientConnected();
    EXPECT_EQ(metrics.activeConnections(), 1u);
    EXPECT_EQ(metrics.totalConnections(), 1u);

    metrics.onRequestReceived();
    EXPECT_EQ(metrics.totalRequests(), 1u);

    metrics.onPositiveResponse();
    EXPECT_EQ(metrics.positiveResponses(), 1u);

    metrics.onNegativeResponse(gw::FailureCode::SourceAddrInvalid);
    EXPECT_EQ(metrics.negativeCount(gw::FailureCode::SourceAddrInvalid), 1u);

    metrics.onNegativeResponse(gw::FailureCode::TargetAddrInvalid);
    EXPECT_EQ(metrics.negativeCount(gw::FailureCode::TargetAddrInvalid), 1u);

    metrics.onNegativeResponse(gw::FailureCode::IntegrityFailure);
    EXPECT_EQ(metrics.negativeCount(gw::FailureCode::IntegrityFailure), 1u);

    metrics.onNegativeResponse(gw::FailureCode::LengthMismatch);
    EXPECT_EQ(metrics.negativeCount(gw::FailureCode::LengthMismatch), 1u);

    metrics.onClientDisconnected();
    EXPECT_EQ(metrics.activeConnections(), 0u);
    EXPECT_EQ(metrics.totalConnections(), 1u);
}

} // namespace
