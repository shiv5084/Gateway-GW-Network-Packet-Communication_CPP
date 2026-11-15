#include "gateway_server.hpp"
#include "connection_handler.hpp"
#include "platform_socket.hpp"
#include "server_metrics.hpp"
#include "logger.hpp"
#include <string>
#include <utility>

namespace gw {

GatewayServer::GatewayServer(uint16_t port)
    : port_(port)
    , lengthValidator_(new LengthValidator())
    , saValidator_(new SourceAddressValidator())
    , taValidator_(new TargetAddressValidator())
    , crcValidator_(new CrcValidator(crc_)) {
    // Assemble Validation Chain: Length -> SA -> TA -> CRC
    lengthValidator_->setNext(saValidator_.get())
                    ->setNext(taValidator_.get())
                    ->setNext(crcValidator_.get());
}

GatewayServer::~GatewayServer() {
    stop();
}

void GatewayServer::start() {
    PlatformSocket::initializePlatform();

    tcpServer_.bind(port_);
    tcpServer_.listen(static_cast<int>(GW_LISTEN_BACKLOG));

    Logger::instance().log(LogLevel::INFO, "SERVER", "Server listening on 0.0.0.0:" + std::to_string(port_));

    tcpServer_.acceptLoop([this](SocketGuard clientGuard, std::string peerEndpoint) {
        ConnectionHandler handler(std::move(clientGuard),
                                  *lengthValidator_,
                                  requestCrypto_,
                                  responseCrypto_,
                                  nibbleSwap_,
                                  responseFactory_,
                                  crc_,
                                  ServerMetrics::instance(),
                                  std::move(peerEndpoint));
        handler.handleClient();
    });
}

void GatewayServer::stop() {
    if (tcpServer_.isRunning()) {
        tcpServer_.stop();
        Logger::instance().log(LogLevel::INFO, "SERVER", "GatewayServer stopped");
    }
}

} // namespace gw
