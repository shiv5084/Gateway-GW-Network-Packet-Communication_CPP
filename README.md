# Gateway Network Packet Communication System (C++11)

A high-performance, robust, and clean-code implementation of a multi-threaded network gateway communication server and diagnostic client in standard C++11.

---

## 1. Overview

The Gateway (GW) acts as a communication bridge between Network Nodes and application services. It receives encrypted requests over TCP, frames them using a two-phase framing mechanism, validates packets via a strict Chain of Responsibility, decrypts and transforms payloads (nibble swapping), and delivers cryptographically secured or negative diagnostic response packets.

---

## 2. Protocol Specification

### 2.1 Packet Format (Big-Endian Network Byte Order)

```text
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|       Source Address          |       Target Address          |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                            Length                             |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|     Payload Data (Length - 1 bytes)...        |      CRC      |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

* **Header (8 bytes):**
  * **Source Address (2 bytes):** Big-endian. Valid node request addresses: `0x0E80` (Primary), `0xE008` (Secondary).
  * **Target Address (2 bytes):** Big-endian. Valid gateway addresses: `0x3108` (Primary), `0x1380` (Secondary).
  * **Length (4 bytes):** Big-endian. Total size of (Payload Data + 1 byte CRC).
* **Body:**
  * **Payload Data ($N$ bytes):** Encrypted with XOR `0xAA` for requests.
  * **CRC (1 byte):** CRC-8 checksum computed over the payload data (Polynomial $x^8 + x^2 + x + 1 = \text{0x07}$, initial value `0x00`).

### 2.2 Response Packets

* **Positive Response:**
  * Source Address: Target Address from request (`0x3108` or `0x1380`).
  * Target Address: Source Address from request (`0x0E80` or `0xE008`).
  * Payload: Request payload decrypted with XOR `0xAA`, transformed via high/low nibble swap, encrypted with XOR `0x55`.
  * CRC: CRC-8 computed over the encrypted transformed payload.
* **Negative Response (10 bytes fixed):**
  * Sent immediately upon validation failure.
  * Length: `2` (1 byte failure code + 1 byte CRC).
  * Failure Code: **Unencrypted** single-byte error identifier:
    * `0x01` — `SourceAddrInvalid`: Source address not recognized.
    * `0x02` — `TargetAddrInvalid`: Target address not recognized.
    * `0x04` — `IntegrityFailure`: CRC-8 mismatch over payload.
    * `0x08` — `LengthMismatch`: Length field inconsistency (< 2 or frame size mismatch).
  * CRC: CRC-8 computed over the single failure code byte.

---

## 3. Architecture & Design Principles

### 3.1 Design Patterns (GoF & Modern Idioms)

| Pattern | Component | Purpose |
|---|---|---|
| **Adapter** | `PlatformSocket` | Encapsulates OS socket primitives (Winsock2 / POSIX BSD sockets) behind `ISocket`. |
| **RAII Resource Manager** | `SocketGuard` | Automatically closes OS socket handles on scope exit or exception. |
| **Strategy** | `ICryptoStrategy`, `XorCryptoStrategy` | Pluggable cryptographic algorithm interface (0xAA request, 0x55 response). |
| **Chain of Responsibility** | `IValidationHandler`, `BaseValidator`, `LengthValidator`, `SourceAddressValidator`, `TargetAddressValidator`, `CrcValidator` | Decoupled fail-fast validation in strict precedence order (0x08 $\to$ 0x01 $\to$ 0x02 $\to$ 0x04). |
| **Factory Method** | `ResponseFactory` | Encapsulates construction of positive and negative binary response frames. |
| **Template Method** | `ConnectionHandler` | Enforces fixed client request-response lifecycle with pluggable sub-steps. |
| **Facade** | `GatewayServer` | Simple top-level interface (`start()`, `stop()`) hiding internal subsystem wiring. |
| **Singleton + Observer** | `ServerMetrics`, `Logger` | Thread-safe operational telemetry and structured logging. |

### 3.2 C++ Rule of Zero & Rule of Five

* **Rule of Zero (14 classes):** `Packet`, `Crc8Calculator`, `XorCryptoStrategy`, `NibbleSwapTransform`, `PacketParser`, `StreamFramer`, `BaseValidator`, `LengthValidator`, `SourceAddressValidator`, `TargetAddressValidator`, `CrcValidator`, `ResponseFactory`, `RequestBuilder`, `ResponseParser`.
  * Classes manage no direct raw resources; all special member functions are compiler-generated.
* **Rule of Five (7 classes):** `SocketGuard`, `ConnectionHandler`, `TcpClient`, `TcpServer`, `GatewayServer`, `Logger`, `ServerMetrics`.
  * Types explicitly declare or `= delete` all 5 special member functions to guarantee correct ownership and thread safety.

### 3.3 Clean Code Standards

* **Small Functions:** All methods $\le 20$ lines.
* **Command-Query Separation (CQS):** State-mutating commands return `void`; queries return values without side effects.
* **Meaningful Naming:** Domain nouns for classes; active verbs for methods.
* **Strict Constness & Type Safety:** `constexpr` constants; zero `#define` macros for protocol logic.

---

## 4. Project Directory Structure

```text
├── CMakeLists.txt              # Cross-platform CMake build definition
├── README.md                   # System documentation
├── docs/                       # Architecture, requirement & phase specifications
│   ├── architecture.md
│   ├── phase-wise-implementationPlan.md
│   └── problemStatement.md
├── include/
│   ├── common/                 # Core protocol and platform abstractions
│   │   ├── crc8_calculator.hpp
│   │   ├── gw_config.hpp
│   │   ├── gw_types.hpp
│   │   ├── i_crypto_strategy.hpp
│   │   ├── i_socket.hpp
│   │   ├── i_transform.hpp
│   │   ├── logger.hpp
│   │   ├── nibble_swap_transform.hpp
│   │   ├── packet.hpp
│   │   ├── packet_parser.hpp
│   │   ├── platform_socket.hpp
│   │   ├── socket_guard.hpp
│   │   ├── stream_framer.hpp
│   │   └── xor_crypto_strategy.hpp
│   ├── server/                 # Gateway server subsystem
│   │   ├── base_validator.hpp
│   │   ├── connection_handler.hpp
│   │   ├── crc_validator.hpp
│   │   ├── gateway_server.hpp
│   │   ├── i_validation_handler.hpp
│   │   ├── length_validator.hpp
│   │   ├── response_factory.hpp
│   │   ├── server_metrics.hpp
│   │   ├── source_address_validator.hpp
│   │   ├── target_address_validator.hpp
│   │   └── tcp_server.hpp
│   └── client/                 # Diagnostic client subsystem
│       ├── request_builder.hpp
│       ├── response_parser.hpp
│       └── tcp_client.hpp
├── src/                        # Implementations
│   ├── common/
│   ├── server/
│   └── client/
└── tests/                      # Google Test suite (121 test cases)
    ├── common/
    ├── server/
    ├── client/
    ├── integration/
    └── stress/
```

---

## 5. Build & Test Instructions

### 5.1 Prerequisites

* **C++ Compiler:** GCC 5+, Clang 3.8+, or MSVC 2015+ (C++11 support required)
* **Build System:** CMake 3.20+
* **Build Tool:** Ninja, GNU Make, or Visual Studio

### 5.2 Build Instructions

```bash
# Configure build
cmake -B build

# Compile with zero warnings (-Wall -Wextra -Werror -pedantic)
cmake --build build
```

To build with **AddressSanitizer (ASan)**:
```bash
cmake -B build -DSANITIZE_ADDRESS=ON
cmake --build build
```

### 5.3 Executing Test Suites

```bash
# Run all 121 unit, integration, and stress tests via CTest
ctest --test-dir build --output-on-failure
```

---

## 6. Running Server and Client

### 6.1 Gateway Server (`gw_server`)

```bash
# Start server on default port 13400 with INFO logging
./build/gw_server

# Custom port and debug logging (shows hex dumps & transformation traces)
./build/gw_server --port 13400 --log-level DEBUG
```

### 6.2 Diagnostic Client (`gw_client`)

#### Automated Conformance Mode:
```bash
# Run automated validation scenarios against the server
./build/gw_client --test --port 13400
```

Sample output:
```text
========================================
   Gateway Client Automated Test Mode   
========================================
[PASS] Scenario 1: Valid Request (0x12 -> 0x21)
[PASS] Scenario 2: Invalid Source Address (0x01)
[PASS] Scenario 3: Invalid Target Address (0x02)
[PASS] Scenario 4: Corrupted CRC (0x04)
[PASS] Scenario 5: Length Mismatch (0x08)
----------------------------------------
Summary: 5 passed, 0 failed
========================================
```

#### Interactive CLI Mode:
```bash
# Connect interactively and input hex bytes
./build/gw_client --port 13400
> 12 34 AB
Positive Response (Decrypted Payload): 21 43 BA
> q
```

---

## 7. Performance & Concurrency Benchmarks

* **Stress Test Verification:**
  * 32 concurrent client threads executing 1,000 requests each (32,000 total requests).
  * **Zero Drops:** 32,000 requests sent $\to$ 32,000 responses received.
  * Verified under thread contention in `tests/stress/test_concurrent_clients.cpp`.
* **Memory Safety:**
  * Complete RAII lifecycle management.
  * Tested with AddressSanitizer (`-DSANITIZE_ADDRESS=ON`) reporting zero leaks and zero memory corruption.
