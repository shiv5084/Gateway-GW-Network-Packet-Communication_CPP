#include "connection_handler.hpp"
#include "stream_framer.hpp"
#include "packet_parser.hpp"
#include "platform_socket.hpp"
#include "gw_config.hpp"
#include "logger.hpp"
#include <stdexcept>
#include <sstream>
#include <iomanip>
#include <utility>

namespace gw {

namespace {

std::string formatHexList(const std::vector<uint8_t>& bytes) {
    std::ostringstream ss;
    ss << std::hex << std::uppercase << std::setfill('0');
    for (size_t i = 0; i < bytes.size(); ++i) {
        if (i > 0) ss << " ";
        ss << std::setw(2) << static_cast<int>(bytes[i]);
    }
    return ss.str();
}

std::string formatHexByte(uint8_t b) {
    std::ostringstream ss;
    ss << std::hex << std::uppercase << std::setfill('0') << std::setw(2) << static_cast<int>(b);
    return ss.str();
}

} // namespace

ConnectionHandler::ConnectionHandler(std::unique_ptr<ISocket> socket,
                                     const IValidationHandler& validator,
                                     const ICryptoStrategy& requestCrypto,
                                     const ICryptoStrategy& responseCrypto,
                                     const ITransform& transform,
                                     const ResponseFactory& responseFactory,
                                     const Crc8Calculator& crcCalculator,
                                     ServerMetrics& metrics,
                                     std::string peerEndpoint)
    : socket_(std::move(socket))
    , validator_(&validator)
    , requestCrypto_(&requestCrypto)
    , responseCrypto_(&responseCrypto)
    , transform_(&transform)
    , responseFactory_(&responseFactory)
    , crcCalculator_(&crcCalculator)
    , metrics_(&metrics)
    , peerEndpoint_(std::move(peerEndpoint)) {}

ConnectionHandler::ConnectionHandler(SocketGuard socketGuard,
                                     const IValidationHandler& validator,
                                     const ICryptoStrategy& requestCrypto,
                                     const ICryptoStrategy& responseCrypto,
                                     const ITransform& transform,
                                     const ResponseFactory& responseFactory,
                                     const Crc8Calculator& crcCalculator,
                                     ServerMetrics& metrics,
                                     std::string peerEndpoint)
    : socket_(new PlatformSocket(socketGuard.release()))
    , validator_(&validator)
    , requestCrypto_(&requestCrypto)
    , responseCrypto_(&responseCrypto)
    , transform_(&transform)
    , responseFactory_(&responseFactory)
    , crcCalculator_(&crcCalculator)
    , metrics_(&metrics)
    , peerEndpoint_(std::move(peerEndpoint)) {}

ConnectionHandler::ConnectionHandler(std::unique_ptr<ISocket> socket,
                                     const IValidationHandler& validator,
                                     const ICryptoStrategy& requestCrypto,
                                     const ICryptoStrategy& responseCrypto,
                                     const ITransform& transform,
                                     const ResponseFactory& responseFactory,
                                     ServerMetrics& metrics)
    : socket_(std::move(socket))
    , validator_(&validator)
    , requestCrypto_(&requestCrypto)
    , responseCrypto_(&responseCrypto)
    , transform_(&transform)
    , responseFactory_(&responseFactory)
    , crcCalculator_(nullptr)
    , metrics_(&metrics)
    , peerEndpoint_("unknown") {}

void ConnectionHandler::handleClient() {
    if (!socket_ || !socket_->isValid()) {
        return;
    }
    if (metrics_ != nullptr) {
        metrics_->onClientConnected();
    }
    // 1. Connection event
    Logger::instance().log(LogLevel::INFO, "SERVER", "Client connected from " + peerEndpoint_);

    try {
        while (true) {
            std::vector<uint8_t> frameData = readFrame();
            if (frameData.empty()) {
                break; // Orderly client disconnect
            }

            // 2. RX Hex Dump
            Logger::instance().hexDump(LogLevel::DEBUG, "FRAMER", "RX",
                                       frameData.data(), frameData.size());

            if (metrics_ != nullptr) {
                metrics_->onRequestReceived();
            }

            try {
                Packet req = parseFrame(frameData);
                FailureCode code = validatePacket(req);

                std::vector<uint8_t> respFrame;
                if (code == FailureCode::None) {
                    // 3. Validation result (Success)
                    std::ostringstream valSs;
                    valSs << "Validation passed (SA=0x"
                          << std::hex << std::uppercase << std::setfill('0') << std::setw(4) << req.sourceAddr()
                          << ", TA=0x" << std::setw(4) << req.targetAddr() << ")";
                    Logger::instance().log(LogLevel::INFO, "VALID", valSs.str());

                    // 4. Transformation trace
                    std::vector<uint8_t> transformed = transformPayload(req);

                    respFrame = buildResponse(req, FailureCode::None, transformed);
                    if (metrics_ != nullptr) {
                        metrics_->onPositiveResponse();
                    }
                } else {
                    // 3. Validation result (Failure)
                    std::string failMsg = std::string("Validation failed: ") + failureCodeToString(code);
                    Logger::instance().log(LogLevel::WARN, "VALID", failMsg);

                    respFrame = buildResponse(req, code, {});
                    if (metrics_ != nullptr) {
                        metrics_->onNegativeResponse(code);
                    }
                }

                // 5. TX Hex Dump
                Logger::instance().hexDump(LogLevel::DEBUG, "FRAMER", "TX",
                                           respFrame.data(), respFrame.size());

                // 6. Response delivery confirmation
                sendResponse(respFrame);
                Logger::instance().log(LogLevel::INFO, "SERVER",
                    "Response delivered (" + std::to_string(respFrame.size()) + " bytes)");

            } catch (const std::invalid_argument& ex) {
                // Protocol violation: Length mismatch or malformed frame
                std::string failMsg = std::string("Validation failed: ") +
                    failureCodeToString(FailureCode::LengthMismatch);
                Logger::instance().log(LogLevel::WARN, "VALID", failMsg);

                uint16_t reqSa = (frameData.size() >= 2)
                    ? static_cast<uint16_t>((static_cast<uint16_t>(frameData[0]) << 8) | frameData[1])
                    : GW_ADDR_NODE_PRIMARY;
                uint16_t reqTa = (frameData.size() >= 4)
                    ? static_cast<uint16_t>((static_cast<uint16_t>(frameData[2]) << 8) | frameData[3])
                    : GW_ADDR_GW_PRIMARY;

                Packet dummyReq(reqSa, reqTa, 2, {}, 0);
                std::vector<uint8_t> respFrame = buildResponse(dummyReq, FailureCode::LengthMismatch, {});
                if (metrics_ != nullptr) {
                    metrics_->onNegativeResponse(FailureCode::LengthMismatch);
                }

                Logger::instance().hexDump(LogLevel::DEBUG, "FRAMER", "TX",
                                           respFrame.data(), respFrame.size());
                sendResponse(respFrame);
                Logger::instance().log(LogLevel::INFO, "SERVER",
                    "Response delivered (" + std::to_string(respFrame.size()) + " bytes)");
            }
        }
    } catch (const std::exception& ex) {
        Logger::instance().log(LogLevel::ERROR, "SERVER",
            "Exception in connection handler: " + std::string(ex.what()));
    } catch (...) {
        Logger::instance().log(LogLevel::ERROR, "SERVER",
            "Unknown exception in connection handler");
    }

    if (metrics_ != nullptr) {
        metrics_->onClientDisconnected();
    }
    Logger::instance().log(LogLevel::INFO, "SERVER", "Client disconnected (" + peerEndpoint_ + ")");
}

std::vector<uint8_t> ConnectionHandler::readFrame() {
    return StreamFramer::readFrame(*socket_);
}

Packet ConnectionHandler::parseFrame(const std::vector<uint8_t>& data) {
    return PacketParser::parse(data);
}

FailureCode ConnectionHandler::validatePacket(const Packet& packet) {
    if (validator_ != nullptr) {
        return validator_->validate(packet);
    }
    return FailureCode::None;
}

std::vector<uint8_t> ConnectionHandler::transformPayload(const Packet& packet) {
    std::vector<uint8_t> decrypted = packet.payload();
    if (requestCrypto_ != nullptr) {
        requestCrypto_->process(decrypted.data(), decrypted.size());
    }

    std::vector<uint8_t> swapped = decrypted;
    if (transform_ != nullptr) {
        transform_->apply(swapped.data(), swapped.size());
    }

    std::vector<uint8_t> encrypted = swapped;
    if (responseCrypto_ != nullptr) {
        responseCrypto_->process(encrypted.data(), encrypted.size());
    }

    uint8_t crc = 0;
    if (crcCalculator_ != nullptr) {
        crc = crcCalculator_->compute(encrypted.data(), encrypted.size());
    }

    // Format transformation trace: Decrypt: [XX] → Swap: [YY] → Encrypt: [ZZ] → CRC: [WW]
    std::ostringstream traceSs;
    traceSs << "Decrypt: [" << formatHexList(decrypted) << "] "
            << "\xe2\x86\x92 Swap: [" << formatHexList(swapped) << "] "
            << "\xe2\x86\x92 Encrypt: [" << formatHexList(encrypted) << "] "
            << "\xe2\x86\x92 CRC: [" << formatHexByte(crc) << "]";
    Logger::instance().log(LogLevel::DEBUG, "TRANS", traceSs.str());

    return swapped;
}

std::vector<uint8_t> ConnectionHandler::buildResponse(const Packet& req,
                                                     FailureCode code,
                                                     const std::vector<uint8_t>& payload) {
    if (responseFactory_ != nullptr) {
        return responseFactory_->create(req, code, payload);
    }
    return std::vector<uint8_t>{};
}

void ConnectionHandler::sendResponse(const std::vector<uint8_t>& frame) {
    if (socket_ && socket_->isValid() && !frame.empty()) {
        socket_->send(frame.data(), frame.size());
    }
}

} // namespace gw
