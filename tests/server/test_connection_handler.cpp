#include <gtest/gtest.h>
#include "connection_handler.hpp"
#include "i_socket.hpp"
#include "length_validator.hpp"
#include "source_address_validator.hpp"
#include "target_address_validator.hpp"
#include "crc_validator.hpp"
#include "xor_crypto_strategy.hpp"
#include "nibble_swap_transform.hpp"
#include "response_factory.hpp"
#include "server_metrics.hpp"
#include "packet_parser.hpp"
#include "gw_config.hpp"
#include <cstring>
#include <algorithm>

namespace {

class MockConnectionSocket : public gw::ISocket {
public:
    explicit MockConnectionSocket(std::vector<uint8_t> rxData)
        : rxBuffer_(std::move(rxData)) {}

    int send(const uint8_t* data, size_t length) override {
        txBuffer_.insert(txBuffer_.end(), data, data + length);
        return static_cast<int>(length);
    }

    ssize_t recv(uint8_t* buffer, size_t length) override {
        if (readPos_ >= rxBuffer_.size()) {
            return 0; // EOF
        }
        size_t available = rxBuffer_.size() - readPos_;
        size_t toRead = (std::min)(length, available);
        std::memcpy(buffer, rxBuffer_.data() + readPos_, toRead);
        readPos_ += toRead;
        return static_cast<ssize_t>(toRead);
    }

    void close() override {
        closed_ = true;
    }

    bool isValid() const noexcept override {
        return !closed_;
    }

    const std::vector<uint8_t>& getTxBuffer() const noexcept {
        return txBuffer_;
    }

private:
    std::vector<uint8_t> rxBuffer_;
    std::vector<uint8_t> txBuffer_;
    size_t readPos_{0};
    bool closed_{false};
};

class ConnectionHandlerMockTest : public ::testing::Test {
protected:
    void SetUp() override {
        lengthVal_.setNext(&saVal_)->setNext(&taVal_)->setNext(&crcVal_);
        gw::ServerMetrics::instance().reset();
    }

    gw::Crc8Calculator crcCalc_;
    gw::XorCryptoStrategy reqCrypto_{gw::GW_KEY_REQUEST};
    gw::XorCryptoStrategy respCrypto_{gw::GW_KEY_RESPONSE};
    gw::NibbleSwapTransform transform_;
    gw::LengthValidator lengthVal_;
    gw::SourceAddressValidator saVal_;
    gw::TargetAddressValidator taVal_;
    gw::CrcValidator crcVal_{crcCalc_};
    gw::ResponseFactory respFactory_{respCrypto_, crcCalc_};
};

TEST_F(ConnectionHandlerMockTest, ValidRequestProducesPositiveResponse) {
    // Valid Request: SA=0x0E80, TA=0x3108, payload=[0xB8] (raw 0x12 ^ 0xAA), CRC=0x21
    std::vector<uint8_t> reqFrame = {
        0x0E, 0x80,
        0x31, 0x08,
        0x00, 0x00, 0x00, 0x02,
        0xB8,
        0x21
    };

    std::unique_ptr<MockConnectionSocket> socket(new MockConnectionSocket(reqFrame));
    MockConnectionSocket* rawSocket = socket.get();

    gw::ConnectionHandler handler(std::move(socket),
                                  lengthVal_,
                                  reqCrypto_,
                                  respCrypto_,
                                  transform_,
                                  respFactory_,
                                  gw::ServerMetrics::instance());
    handler.handleClient();

    // Verify response frame
    const std::vector<uint8_t>& tx = rawSocket->getTxBuffer();
    std::vector<uint8_t> expectedTx = {
        0x31, 0x08,             // Swapped SA
        0x0E, 0x80,             // Swapped TA
        0x00, 0x00, 0x00, 0x02, // Length: 2
        0x74,                   // Transformed payload (0x12 -> nibble swap 0x21 -> 0x21 ^ 0x55 = 0x74)
        0x4B                    // CRC
    };
    EXPECT_EQ(tx, expectedTx);
    EXPECT_EQ(gw::ServerMetrics::instance().totalRequests(), 1u);
    EXPECT_EQ(gw::ServerMetrics::instance().positiveResponses(), 1u);
}

TEST_F(ConnectionHandlerMockTest, InvalidSourceAddressProducesNegativeResponse) {
    // Invalid SA: 0xFFFF
    std::vector<uint8_t> reqFrame = {
        0xFF, 0xFF,
        0x31, 0x08,
        0x00, 0x00, 0x00, 0x02,
        0xB8,
        0x21
    };

    std::unique_ptr<MockConnectionSocket> socket(new MockConnectionSocket(reqFrame));
    MockConnectionSocket* rawSocket = socket.get();

    gw::ConnectionHandler handler(std::move(socket),
                                  lengthVal_,
                                  reqCrypto_,
                                  respCrypto_,
                                  transform_,
                                  respFactory_,
                                  gw::ServerMetrics::instance());
    handler.handleClient();

    const std::vector<uint8_t>& tx = rawSocket->getTxBuffer();
    ASSERT_EQ(tx.size(), 10u);
    EXPECT_EQ(tx[0], 0x31);
    EXPECT_EQ(tx[1], 0x08);
    EXPECT_EQ(tx[2], 0xFF);
    EXPECT_EQ(tx[3], 0xFF);
    EXPECT_EQ(tx[8], 0x01); // FailureCode::SourceAddrInvalid

    EXPECT_EQ(gw::ServerMetrics::instance().totalRequests(), 1u);
    EXPECT_EQ(gw::ServerMetrics::instance().negativeCount(gw::FailureCode::SourceAddrInvalid), 1u);
}

} // namespace
