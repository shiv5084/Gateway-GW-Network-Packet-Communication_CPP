# Problem Statement — Gateway (GW) Network Packet Communication

## Overview

The goal of this project is to implement a **Gateway (GW) application** that operates in a Client/Server environment over TCP/IP. The Gateway acts as a **protocol translator**, converting packets between a proprietary *Network Node* wire format and a plain (normal) payload format, and routing responses back to the originating client.

---

## System Context

```
Client  <──────────────────────────────>  GW Application
         (Network Node Packet Format)
```

The GW application:
- Listens for incoming requests from clients on **TCP port 13400** (loopback or any IP).
- Accepts **multiple concurrent requests** and must process every one of them — no request may be dropped.
- Validates each request, decrypts the payload, transforms it, re-encrypts it, and returns a response.

---

## Packet Formats

### Network Node — Request Packet

| Field                   | Size      | Description |
|-------------------------|-----------|-------------|
| Source Address          | 2 bytes   | `0x0E80` or `0xE008` |
| Target Address          | 2 bytes   | `0x3108` or `0x1380` |
| Length                  | 4 bytes   | Size of (Encrypted Payload Data + CRC) |
| Encrypted Payload Data  | n × 1 byte | Encrypted payload bytes |
| CRC                     | 1 byte    | CRC-8 integrity check over the payload |

**Encryption (Request):**
```
Encrypted_Byte[i] = Payload_Byte[i] XOR 0xAA
```

---

### Network Node — Positive Response Packet

| Field                   | Size      | Description |
|-------------------------|-----------|-------------|
| Source Address          | 2 bytes   | `0x3108` or `0x1380` |
| Target Address          | 2 bytes   | `0x0E80` or `0xE008` |
| Length                  | 4 bytes   | Size of (Encrypted Payload Data + CRC) |
| Encrypted Payload Data  | n × 1 byte | Encrypted transformed payload bytes |
| CRC                     | 1 byte    | CRC-8 integrity check over the payload |

**Encryption (Positive Response):**
```
Encrypted_Byte[i] = Transformed_Byte[i] XOR 0x55
```

---

### Network Node — Negative Response Packet

Sent when validation of the incoming request fails.

| Field          | Size    | Description |
|----------------|---------|-------------|
| Source Address | 2 bytes | `0x3108` or `0x1380` |
| Target Address | 2 bytes | `0x0E80` or `0xE008` |
| Length         | 4 bytes | Size of (Failure Code + CRC) |
| Failure Code   | 1 byte  | Error code (see table below) — **not encrypted** |
| CRC            | 1 byte  | CRC-8 integrity check |

**Failure Codes:**

| Code   | Meaning                  |
|--------|--------------------------|
| `0x01` | Source Address Invalid   |
| `0x02` | Target Address Invalid   |
| `0x04` | Integrity Failure (CRC mismatch) |
| `0x08` | Payload Length Mismatch  |

---

## GW Application — Processing Logic

For every received request the GW must perform the following steps **in order**:

1. **Validate the request** — check all failure conditions (source address, target address, CRC integrity, and payload length). If any check fails, send the appropriate **Negative Response** immediately with the corresponding failure code.

2. **Decrypt the payload** — if all validations pass, extract the raw payload by reversing the XOR encryption:
   ```
   Payload_Byte[i] = Encrypted_Byte[i] XOR 0xAA
   ```

3. **Transform the payload** — apply a nibble-swap operation to every payload byte:
   ```
   Transformed_Byte[i] = ((Payload_Byte[i] & 0x0F) << 4) | ((Payload_Byte[i] & 0xF0) >> 4)
   ```

4. **Re-encrypt and send a Positive Response** — encrypt the transformed payload using `XOR 0x55`, compute CRC-8, and send the response packet back to the client.

---

## Key Requirements

> [!IMPORTANT]
> - The server **must** listen on **TCP port 13400**.
> - **No request must ever be skipped** — all concurrent requests must be processed and responded to.
> - Multiple clients may send requests simultaneously; the server must handle them concurrently.
> - CRC-8 is used for integrity verification of all payload data.
> - Failure Code bytes in a negative response are **never** encrypted.

---

## CRC Algorithm

Integrity of the payload is checked and computed using the **CRC-8** algorithm. The CRC is calculated over the raw (decrypted) payload data before encryption and is included as the last byte of every packet.

