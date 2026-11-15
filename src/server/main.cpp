#include "gateway_server.hpp"
#include "server_metrics.hpp"
#include "logger.hpp"
#include "platform_socket.hpp"
#include <iostream>
#include <csignal>
#include <cstdlib>
#include <string>

namespace {
gw::GatewayServer* g_server = nullptr;

void signalHandler(int signum) {
    gw::Logger::instance().log(gw::LogLevel::INFO, "SERVER",
        "Signal received (" + std::to_string(signum) + "), initiating clean shutdown");
    if (g_server != nullptr) {
        g_server->stop();
    }
}
} // namespace

int main(int argc, char* argv[]) {
    uint16_t port = gw::DEFAULT_PORT;

    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "--port" && i + 1 < argc) {
            port = static_cast<uint16_t>(std::atoi(argv[++i]));
        } else if (arg == "--log-level" && i + 1 < argc) {
            std::string level = argv[++i];
            if (level == "DEBUG") gw::Logger::instance().setLevel(gw::LogLevel::DEBUG);
            else if (level == "WARN") gw::Logger::instance().setLevel(gw::LogLevel::WARN);
            else if (level == "ERROR") gw::Logger::instance().setLevel(gw::LogLevel::ERROR);
            else gw::Logger::instance().setLevel(gw::LogLevel::INFO);
        }
    }

    if (!gw::PlatformSocket::initializePlatform()) {
        std::cerr << "Failed to initialize socket platform" << std::endl;
        return 1;
    }

    gw::GatewayServer server(port);
    g_server = &server;

    std::signal(SIGINT, signalHandler);
    std::signal(SIGTERM, signalHandler);

    gw::Logger::instance().log(gw::LogLevel::INFO, "SERVER", "Starting Gateway Server on port " + std::to_string(port));
    try {
        server.start();
    } catch (const std::exception& ex) {
        gw::Logger::instance().log(gw::LogLevel::ERROR, "SERVER", std::string("Server fatal error: ") + ex.what());
    }

    g_server = nullptr;
    gw::ServerMetrics::instance().dump();
    gw::PlatformSocket::cleanupPlatform();
    return 0;
}
