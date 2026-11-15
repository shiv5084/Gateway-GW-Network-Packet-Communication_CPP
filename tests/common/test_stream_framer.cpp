#include <gtest/gtest.h>
#include "stream_framer.hpp"
#include "i_socket.hpp"
#include <algorithm>
#include <cstring>

namespace {

class MockSocket : public gw::ISocket {
public:
    explicit MockSocket(std::vector<uint8_t> rxData)
        : rxBuffer_(std::move(rxData)) {}

    int send(const uint8_t* data, size_t length) override {
        txBuffer_.insert(txBuffer_.end(), data, data + length);
        return static_cast<int>(length);
    }

    ssize_t recv(uint8_t* buffer, size_t length) override {
        if (readPos_ >= rxBuffer_.size()) {
            return 0; // EOF / closed
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

TEST(StreamFramerTest, RecvExactReadsFullCount) {
    std::vector<uint8_t> input = {0x01, 0x02, 0x03, 0x04, 0x05};
    MockSocket socket(input);

    uint8_t out[5];
    ssize_t read = gw::StreamFramer::recvExact(socket, out, 5);

    EXPECT_EQ(read, 5);
    EXPECT_EQ(std::memcmp(out, input.data(), 5), 0);
}

TEST(StreamFramerTest, RecvExactReturnsZeroOnImmediateEof) {
    MockSocket socket({});
    uint8_t out[5];
    ssize_t read = gw::StreamFramer::recvExact(socket, out, 5);
    EXPECT_EQ(read, 0);
}

TEST(StreamFramerTest, RecvExactReturnsNegativeOneOnPartialEof) {
    std::vector<uint8_t> input = {0x01, 0x02}; // only 2 bytes available
    MockSocket socket(input);
    uint8_t out[5];
    ssize_t read = gw::StreamFramer::recvExact(socket, out, 5);
    EXPECT_EQ(read, -1);
}

TEST(StreamFramerTest, ReadFrameReadsCompleteValidFrame) {
    std::vector<uint8_t> frameData = {
        0x0E, 0x80,             // SA: 0x0E80
        0x31, 0x08,             // TA: 0x3108
        0x00, 0x00, 0x00, 0x02, // Length: 2
        0xB8,                   // Payload
        0x21                    // CRC
    };
    MockSocket socket(frameData);

    std::vector<uint8_t> frame = gw::StreamFramer::readFrame(socket);
    EXPECT_EQ(frame, frameData);
}

TEST(StreamFramerTest, ReadFrameReturnsEmptyOnImmediateEof) {
    MockSocket socket({});
    std::vector<uint8_t> frame = gw::StreamFramer::readFrame(socket);
    EXPECT_TRUE(frame.empty());
}

TEST(StreamFramerTest, ReadFrameThrowsOnTruncatedHeader) {
    std::vector<uint8_t> shortHeader = {0x0E, 0x80, 0x31, 0x08}; // only 4 bytes
    MockSocket socket(shortHeader);
    EXPECT_THROW(gw::StreamFramer::readFrame(socket), std::runtime_error);
}

TEST(StreamFramerTest, ReadFrameThrowsOnTruncatedBody) {
    std::vector<uint8_t> truncatedBody = {
        0x0E, 0x80,
        0x31, 0x08,
        0x00, 0x00, 0x00, 0x05, // Length = 5, expects 5 body bytes
        0x01, 0x02              // Only 2 body bytes provided
    };
    MockSocket socket(truncatedBody);
    EXPECT_THROW(gw::StreamFramer::readFrame(socket), std::runtime_error);
}

} // namespace
