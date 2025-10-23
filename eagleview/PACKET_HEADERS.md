# Packet Header Decoding Documentation

## Overview
The WASM packet decoder now extracts **all available header fields** from network packets at Layers 2, 3, and 4.

## Decoded Structure

### Layer 2 (Ethernet)
```typescript
l2?: {
  srcMac?: string           // Source MAC address (e.g., "aa:bb:cc:dd:ee:ff")
  dstMac?: string           // Destination MAC address
  etherType?: number        // EtherType field (e.g., 0x0800 for IPv4)
  etherTypeName?: string    // Human-readable name (e.g., "IPv4", "ARP")
  vlan?: number             // VLAN ID if 802.1Q tag is present
}
```

### Layer 3 (IP)
```typescript
l3?: {
  proto?: 'IPv4' | 'IPv6' | 'ARP'
  src?: string              // Source IP address
  dst?: string              // Destination IP address
  
  // === IPv4 Specific Fields ===
  version?: number          // IP version (always 4 for IPv4)
  headerLen?: number        // Header length in 32-bit words (typically 5)
  tos?: number              // Type of Service / DSCP
  totalLen?: number         // Total packet length in bytes
  identification?: number   // Fragment identification
  flags?: number            // Flags (bit 0: reserved, bit 1: DF, bit 2: MF)
  fragmentOffset?: number   // Fragment offset (in 8-byte blocks)
  ttl?: number              // Time to Live (hop count)
  protocol?: number         // Protocol number (6=TCP, 17=UDP, 1=ICMP)
  checksum?: number         // IPv4 header checksum
  
  // === IPv6 Specific Fields ===
  trafficClass?: number     // Traffic class (QoS)
  flowLabel?: number        // Flow label (20-bit)
  payloadLen?: number       // Payload length in bytes
  nextHeader?: number       // Next header type (similar to IPv4 protocol)
  hopLimit?: number         // Hop limit (similar to IPv4 TTL)
}
```

### Layer 4 (Transport)
```typescript
l4?: {
  proto?: 'TCP' | 'UDP' | 'ICMPv4' | 'ICMPv6'
  srcPort?: number          // Source port (TCP/UDP only)
  dstPort?: number          // Destination port (TCP/UDP only)
  
  // === TCP Specific Fields ===
  tcpFlags?: string         // Flags as comma-separated string (e.g., "SYN,ACK")
  tcpSeq?: number           // Sequence number
  tcpAck?: number           // Acknowledgment number
  tcpWindow?: number        // Window size
  tcpChecksum?: number      // TCP checksum
  tcpUrgent?: number        // Urgent pointer
  tcpDataOffset?: number    // Data offset in 32-bit words (header length)
  
  // === UDP Specific Fields ===
  udpLen?: number           // UDP datagram length (header + data)
  udpChecksum?: number      // UDP checksum
  
  // === ICMP Specific Fields ===
  icmpType?: number         // ICMP message type (e.g., 8=Echo Request)
  icmpCode?: number         // ICMP code (subtype)
  icmpChecksum?: number     // ICMP checksum
}
```

### Additional Fields
```typescript
summary: string             // Human-readable packet summary
protocolTag: string         // Primary protocol tag (e.g., "TCP", "DNS")
appTag?: string            // Application protocol tag (e.g., "HTTP", "TLS")
description?: string       // Multi-line Wireshark-style description
meta?: {                   // Additional protocol-specific metadata
  arp?: { op?: number; spa?: string; tpa?: string }
  dns?: { id: number; qr: boolean; name?: string; qtype?: number; qtypeName?: string }
  tcp?: { flags: number }
}
```

## Examples

### TCP Packet Example
```json
{
  "l2": {
    "srcMac": "aa:bb:cc:dd:ee:ff",
    "dstMac": "00:11:22:33:44:55",
    "etherType": 2048,
    "etherTypeName": "IPv4"
  },
  "l3": {
    "proto": "IPv4",
    "src": "192.168.1.100",
    "dst": "8.8.8.8",
    "version": 4,
    "headerLen": 5,
    "tos": 0,
    "totalLen": 60,
    "identification": 4660,
    "flags": 2,
    "fragmentOffset": 0,
    "ttl": 64,
    "protocol": 6,
    "checksum": 0
  },
  "l4": {
    "proto": "TCP",
    "srcPort": 1234,
    "dstPort": 80,
    "tcpFlags": "SYN",
    "tcpSeq": 1,
    "tcpAck": 0,
    "tcpWindow": 29200,
    "tcpChecksum": 0,
    "tcpUrgent": 0,
    "tcpDataOffset": 5
  },
  "summary": "TCP 1234 → 80",
  "protocolTag": "TCP"
}
```

### UDP Packet Example
```json
{
  "l2": {
    "srcMac": "aa:bb:cc:dd:ee:ff",
    "dstMac": "00:11:22:33:44:55",
    "etherType": 2048,
    "etherTypeName": "IPv4"
  },
  "l3": {
    "proto": "IPv4",
    "src": "192.168.1.100",
    "dst": "8.8.8.4",
    "version": 4,
    "headerLen": 5,
    "tos": 0,
    "totalLen": 44,
    "identification": 4660,
    "flags": 0,
    "fragmentOffset": 0,
    "ttl": 64,
    "protocol": 17,
    "checksum": 0
  },
  "l4": {
    "proto": "UDP",
    "srcPort": 1234,
    "dstPort": 53,
    "udpLen": 20,
    "udpChecksum": 0
  },
  "summary": "UDP 1234 → 53",
  "protocolTag": "UDP"
}
```

### ICMP Packet Example
```json
{
  "l2": {
    "srcMac": "aa:bb:cc:dd:ee:ff",
    "dstMac": "00:11:22:33:44:55",
    "etherType": 2048,
    "etherTypeName": "IPv4"
  },
  "l3": {
    "proto": "IPv4",
    "src": "192.168.1.100",
    "dst": "8.8.8.8",
    "version": 4,
    "headerLen": 5,
    "tos": 0,
    "totalLen": 84,
    "identification": 4660,
    "flags": 0,
    "fragmentOffset": 0,
    "ttl": 64,
    "protocol": 1,
    "checksum": 0
  },
  "l4": {
    "proto": "ICMP",
    "icmpType": 8,
    "icmpCode": 0,
    "icmpChecksum": 0
  },
  "summary": "ICMP type 8 code 0",
  "protocolTag": "ICMP"
}
```

## Field Descriptions

### IPv4 Flags
- Bit 0: Reserved (must be 0)
- Bit 1: Don't Fragment (DF)
- Bit 2: More Fragments (MF)

### TCP Flags
Represented as comma-separated string:
- `FIN`: Finish connection
- `SYN`: Synchronize sequence numbers
- `RST`: Reset connection
- `PSH`: Push data immediately
- `ACK`: Acknowledgment
- `URG`: Urgent pointer is valid
- `ECE`: ECN Echo
- `CWR`: Congestion Window Reduced

### Common ICMP Types (IPv4)
- 0: Echo Reply
- 3: Destination Unreachable
- 5: Redirect
- 8: Echo Request
- 11: Time Exceeded

### Common Protocol Numbers
- 1: ICMP
- 6: TCP
- 17: UDP
- 41: IPv6 encapsulation
- 47: GRE
- 50: ESP
- 51: AH
- 58: ICMPv6

## Usage in Frontend

```typescript
import { decodePacket } from './lib/decoders'
import type { Decoded } from './lib/decoders'

const packet: ParsedPacket = { /* ... */ }
const decoded: Decoded = decodePacket(packet)

// Access all header fields
console.log('Source MAC:', decoded.l2?.srcMac)
console.log('Source IP:', decoded.l3?.src)
console.log('TTL:', decoded.l3?.ttl)
console.log('TCP Seq:', decoded.l4?.tcpSeq)
console.log('TCP Window:', decoded.l4?.tcpWindow)

// Display multi-line description (Wireshark-style)
if (decoded.description) {
  console.log(decoded.description)
  // Output:
  // Frame: Packet, 66 bytes on wire (528 bits), 66 bytes captured (528 bits)
  // Ethernet II, Src: 02:00:00:00:00:0f (02:00:00:00:00:0f), Dst: 02:00:00:00:00:1a (02:00:00:00:00:1a)
  // Internet Protocol Version 4, Src: 10.0.0.26, Dst: 8.8.8.8
  // User Datagram Protocol, Src Port: 53000, Dst Port: 53
  // Domain Name System (query)
}
```

## Notes

- All fields are optional and will only be present when the corresponding protocol is detected
- Checksum values may be 0 in test data or offloaded packets
- The WASM decoder handles both big-endian network byte order and correct bit field extraction
- Fragment offset is measured in 8-byte units; multiply by 8 to get byte offset
- TCP data offset is measured in 32-bit words; multiply by 4 to get header length in bytes
