#ifndef GW_CONNECTION_HANDLER_HPP
#define GW_CONNECTION_HANDLER_HPP

#include "i_socket.hpp"
#include "socket_guard.hpp"
#include "i_validation_handler.hpp"
#include "i_crypto_strategy.hpp"
#include "i_transform.hpp"
#include "response_factory.hpp"
#include "crc8_calculator.hpp"
#include "server_metrics.hpp"
#include "packet.hpp"
#include <memory>
#include <vector>
#include <string>

namespace gw {

/**
 * @brief Handles a single client connection using the Template Method pattern.
 *
 * Implements structured logging at every pipeline stage (P5.1 - P5.4).
 * Enforces Small Functions (each step <= 20 lines) and Composition over Inheritance.
 * Follows Rule of Five (move-only): owns std::unique_ptr<ISocket>.
 */
class ConnectionHandler {
public:
    ConnectionHandler(std::unique_ptr<ISocket> socket,
                      const IValidationHandler& validator,
                      const ICryptoStrategy& requestCrypto,
                      const ICryptoStrategy& responseCrypto,
                      const ITransform& transform,
                      const ResponseFactory& responseFactory,
                      const Crc8Calculator& crcCalculator,
                      ServerMetrics& metrics,
                      std::string peerEndpoint = "unknown");

    ConnectionHandler(SocketGuard socketGuard,
                      const IValidationHandler& validator,
                      const ICryptoStrategy& requestCrypto,
                      const ICryptoStrategy& responseCrypto,
                      const ITransform& transform,
                      const ResponseFactory& responseFactory,
                      const Crc8Calculator& crcCalculator,
                      ServerMetrics& metrics,
                      std::string peerEndpoint = "unknown");

    // Overload for backward compatibility
    ConnectionHandler(std::unique_ptr<ISocket> socket,
                      const IValidationHandler& validator,
                      const ICryptoStrategy& requestCrypto,
                      const ICryptoStrategy& responseCrypto,
                      const ITransform& transform,
                      const ResponseFactory& responseFactory,
                      ServerMetrics& metrics);

    // Rule of Five: move-only semantics
    ~ConnectionHandler() = default;
    ConnectionHandler(const ConnectionHandler&) = delete;
    ConnectionHandler& operator=(const ConnectionHandler&) = delete;
    ConnectionHandler(ConnectionHandler&&) = default;
    ConnectionHandler& operator=(ConnectionHandler&&) = default;

    /**
     * @brief Template Method executing the request-response processing pipeline.
     */
    void handleClient();

private:
    std::vector<uint8_t> readFrame();
    Packet parseFrame(const std::vector<uint8_t>& data);
    FailureCode validatePacket(const Packet& packet);
    std::vector<uint8_t> transformPayload(const Packet& packet);
    std::vector<uint8_t> buildResponse(const Packet& req,
                                       FailureCode code,
                                       const std::vector<uint8_t>& payload);
    void sendResponse(const std::vector<uint8_t>& frame);

    std::unique_ptr<ISocket> socket_;
    const IValidationHandler* validator_{nullptr};
    const ICryptoStrategy* requestCrypto_{nullptr};
    const ICryptoStrategy* responseCrypto_{nullptr};
    const ITransform* transform_{nullptr};
    const ResponseFactory* responseFactory_{nullptr};
    const Crc8Calculator* crcCalculator_{nullptr};
    ServerMetrics* metrics_{nullptr};
    std::string peerEndpoint_{"unknown"};
};

} // namespace gw

#endif // GW_CONNECTION_HANDLER_HPP
