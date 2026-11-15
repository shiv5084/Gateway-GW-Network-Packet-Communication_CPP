#include "crc8_calculator.hpp"
#include "gw_config.hpp"
#include "logger.hpp"
#include "platform_socket.hpp"
#include "request_builder.hpp"
#include "response_parser.hpp"
#include "tcp_client.hpp"
#include "xor_crypto_strategy.hpp"
#include <iomanip>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>

namespace {

void printHex(const std::vector<uint8_t> &data) {
  for (size_t i = 0; i < data.size(); ++i) {
    std::cout << std::hex << std::uppercase << std::setw(2) << std::setfill('0')
              << static_cast<int>(data[i]) << " ";
  }
  std::cout << std::dec << "\n";
}

bool runAutomatedTests(const std::string &ip, uint16_t port) {
  gw::XorCryptoStrategy reqCrypto(gw::GW_KEY_REQUEST);
  gw::XorCryptoStrategy respCrypto(gw::GW_KEY_RESPONSE);
  gw::Crc8Calculator crcCalc;
  gw::RequestBuilder builder(reqCrypto, crcCalc);
  gw::ResponseParser parser(respCrypto, crcCalc);

  int passed = 0;
  int failed = 0;

  std::cout << "\n========================================\n"
            << "   Gateway Client Automated Test Mode   \n"
            << "========================================\n";

  // Test 1: Valid single byte request (0x12 -> positive 0x21)
  try {
    gw::TcpClient client;
    client.connect(ip, port);
    std::vector<uint8_t> frame =
        builder.build(gw::GW_ADDR_NODE_PRIMARY, gw::GW_ADDR_GW_PRIMARY, {0x12});
    client.sendFrame(frame);
    std::vector<uint8_t> respBytes = client.receiveFrame();
    gw::ClientResponse resp = parser.parse(respBytes);

    if (resp.type == gw::ResponseType::Positive &&
        resp.decryptedPayload.size() == 1 && resp.decryptedPayload[0] == 0x21) {
      std::cout << "[PASS] Scenario 1: Valid Request (0x12 -> 0x21)\n";
      ++passed;
    } else {
      std::cout << "[FAIL] Scenario 1: Invalid response payload\n";
      ++failed;
    }
  } catch (const std::exception &e) {
    std::cout << "[FAIL] Scenario 1 Exception: " << e.what() << "\n";
    ++failed;
  }

  // Test 2: Invalid Source Address (0xFFFF -> 0x01)
  try {
    gw::TcpClient client;
    client.connect(ip, port);
    std::vector<uint8_t> frame =
        builder.build(0xFFFF, gw::GW_ADDR_GW_PRIMARY, {0x12});
    client.sendFrame(frame);
    std::vector<uint8_t> respBytes = client.receiveFrame();
    gw::ClientResponse resp = parser.parse(respBytes);

    if (resp.type == gw::ResponseType::Negative &&
        resp.failureCode == gw::FailureCode::SourceAddrInvalid) {
      std::cout << "[PASS] Scenario 2: Invalid Source Address (0x01)\n";
      ++passed;
    } else {
      std::cout << "[FAIL] Scenario 2: Expected failure code 0x01\n";
      ++failed;
    }
  } catch (const std::exception &e) {
    std::cout << "[FAIL] Scenario 2 Exception: " << e.what() << "\n";
    ++failed;
  }

  // Test 3: Invalid Target Address (0x9999 -> 0x02)
  try {
    gw::TcpClient client;
    client.connect(ip, port);
    std::vector<uint8_t> frame =
        builder.build(gw::GW_ADDR_NODE_PRIMARY, 0x9999, {0x12});
    client.sendFrame(frame);
    std::vector<uint8_t> respBytes = client.receiveFrame();
    gw::ClientResponse resp = parser.parse(respBytes);

    if (resp.type == gw::ResponseType::Negative &&
        resp.failureCode == gw::FailureCode::TargetAddrInvalid) {
      std::cout << "[PASS] Scenario 3: Invalid Target Address (0x02)\n";
      ++passed;
    } else {
      std::cout << "[FAIL] Scenario 3: Expected failure code 0x02\n";
      ++failed;
    }
  } catch (const std::exception &e) {
    std::cout << "[FAIL] Scenario 3 Exception: " << e.what() << "\n";
    ++failed;
  }

  // Test 4: Corrupted CRC -> 0x04
  try {
    gw::TcpClient client;
    client.connect(ip, port);
    std::vector<uint8_t> frame = builder.buildInvalid(
        gw::GW_ADDR_NODE_PRIMARY, gw::GW_ADDR_GW_PRIMARY, {0x12}, true, false);
    client.sendFrame(frame);
    std::vector<uint8_t> respBytes = client.receiveFrame();
    gw::ClientResponse resp = parser.parse(respBytes);

    if (resp.type == gw::ResponseType::Negative &&
        resp.failureCode == gw::FailureCode::IntegrityFailure) {
      std::cout << "[PASS] Scenario 4: Corrupted CRC (0x04)\n";
      ++passed;
    } else {
      std::cout << "[FAIL] Scenario 4: Expected failure code 0x04\n";
      ++failed;
    }
  } catch (const std::exception &e) {
    std::cout << "[FAIL] Scenario 4 Exception: " << e.what() << "\n";
    ++failed;
  }

  // Test 5: Length Mismatch -> 0x08
  try {
    gw::TcpClient client;
    client.connect(ip, port);
    // Header length says 1 (invalid: minimum is 2 for payload + CRC)
    std::vector<uint8_t> frame = {
        0x0E, 0x80,             // SA: 0x0E80
        0x31, 0x08,             // TA: 0x3108
        0x00, 0x00, 0x00, 0x01, // Length: 1 (invalid)
        0xB8                    // 1 body byte
    };
    client.sendFrame(frame);
    std::vector<uint8_t> respBytes = client.receiveFrame();
    gw::ClientResponse resp = parser.parse(respBytes);

    if (resp.type == gw::ResponseType::Negative &&
        resp.failureCode == gw::FailureCode::LengthMismatch) {
      std::cout << "[PASS] Scenario 5: Length Mismatch (0x08)\n";
      ++passed;
    } else {
      std::cout << "[FAIL] Scenario 5: Expected failure code 0x08\n";
      ++failed;
    }
  } catch (const std::exception &e) {
    std::cout << "[FAIL] Scenario 5 Exception: " << e.what() << "\n";
    ++failed;
  }

  std::cout << "----------------------------------------\n"
            << "Summary: " << passed << " passed, " << failed << " failed\n"
            << "========================================\n";
  return (failed == 0);
}

} // namespace

int main(int argc, char *argv[]) {
  std::string ip = "127.0.0.1";
  uint16_t port = gw::DEFAULT_PORT;
  bool testMode = false;

  for (int i = 1; i < argc; ++i) {
    std::string arg = argv[i];
    if (arg == "--test") {
      testMode = true;
    } else if (arg == "--ip" && i + 1 < argc) {
      ip = argv[++i];
    } else if (arg == "--port" && i + 1 < argc) {
      port = static_cast<uint16_t>(std::atoi(argv[++i]));
    }
  }

  if (!gw::PlatformSocket::initializePlatform()) {
    std::cerr << "Failed to initialize platform sockets" << std::endl;
    return 1;
  }

  int result = 0;
  if (testMode) {
    bool ok = runAutomatedTests(ip, port);
    result = ok ? 0 : 1;
  } else {
    std::cout << "Connected to Gateway Server at " << ip << ":" << port << "\n";
    std::cout << "Enter hex payload bytes (e.g. 12 34 AB) or 'q' to quit:\n";
    gw::XorCryptoStrategy reqCrypto(gw::GW_KEY_REQUEST);
    gw::XorCryptoStrategy respCrypto(gw::GW_KEY_RESPONSE);
    gw::Crc8Calculator crcCalc;
    gw::RequestBuilder builder(reqCrypto, crcCalc);
    gw::ResponseParser parser(respCrypto, crcCalc);

    try {
      gw::TcpClient client;
      client.connect(ip, port);
      std::string line;
      while (std::cout << "> " && std::getline(std::cin, line)) {
        if (line == "q" || line == "quit")
          break;
        std::istringstream iss(line);
        std::string byteStr;
        std::vector<uint8_t> payload;
        while (iss >> byteStr) {
          payload.push_back(
              static_cast<uint8_t>(std::stoul(byteStr, nullptr, 16)));
        }
        if (payload.empty())
          continue;

        std::vector<uint8_t> frame = builder.build(
            gw::GW_ADDR_NODE_PRIMARY, gw::GW_ADDR_GW_PRIMARY, payload);
        client.sendFrame(frame);
        std::vector<uint8_t> respBytes = client.receiveFrame();
        gw::ClientResponse resp = parser.parse(respBytes);
        if (resp.type == gw::ResponseType::Positive) {
          std::cout << "Positive Response (Decrypted Payload): ";
          printHex(resp.decryptedPayload);
        } else {
          std::cout << "Negative Response: "
                    << gw::failureCodeToString(resp.failureCode) << "\n";
        }
      }
    } catch (const std::exception &e) {
      std::cerr << "Client error: " << e.what() << "\n";
      result = 1;
    }
  }

  gw::PlatformSocket::cleanupPlatform();
  return result;
}
