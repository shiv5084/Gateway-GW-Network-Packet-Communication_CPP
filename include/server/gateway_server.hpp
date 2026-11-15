#ifndef GW_GATEWAY_SERVER_HPP
#define GW_GATEWAY_SERVER_HPP

#include "gw_config.hpp"
#include "tcp_server.hpp"
#include "crc8_calculator.hpp"
#include "xor_crypto_strategy.hpp"
#include "nibble_swap_transform.hpp"
#include "length_validator.hpp"
#include "source_address_validator.hpp"
#include "target_address_validator.hpp"
#include "crc_validator.hpp"
#include "response_factory.hpp"
#include <memory>
#include <cstdint>

namespace gw {

/**
 * @brief Facade class wiring all gateway server subsystems.
 *
 * Exposes simple start() and stop() interface hiding internal wiring.
 * Follows Rule of Five (non-movable):
 * - Destructor signals stop() and joins threads.
 * - Copy and move operations are deleted (owns network threads + state).
 */
class GatewayServer {
public:
    explicit GatewayServer(uint16_t port = DEFAULT_PORT);
    ~GatewayServer();

    // Rule of Five: non-copyable, non-movable facade
    GatewayServer(const GatewayServer&) = delete;
    GatewayServer& operator=(const GatewayServer&) = delete;
    GatewayServer(GatewayServer&&) = delete;
    GatewayServer& operator=(GatewayServer&&) = delete;

    void start();
    void stop();

    bool isRunning() const noexcept { return tcpServer_.isRunning(); }
    uint16_t getPort() const noexcept { return port_; }

private:
    uint16_t port_;
    TcpServer tcpServer_;
    Crc8Calculator crc_;
    XorCryptoStrategy requestCrypto_{GW_KEY_REQUEST};
    XorCryptoStrategy responseCrypto_{GW_KEY_RESPONSE};
    NibbleSwapTransform nibbleSwap_;

    std::unique_ptr<LengthValidator> lengthValidator_;
    std::unique_ptr<SourceAddressValidator> saValidator_;
    std::unique_ptr<TargetAddressValidator> taValidator_;
    std::unique_ptr<CrcValidator> crcValidator_;

    ResponseFactory responseFactory_{responseCrypto_, crc_};
};

} // namespace gw

#endif // GW_GATEWAY_SERVER_HPP
