# Enhanced Packet Decoder

The WASM packet decoder now provides **complete header information** and **Wireshark-style descriptions** for all decoded packets.

## Features

### 1. Complete Header Fields
All available header fields from layers 2-4 are now decoded:

- **Layer 2 (Ethernet)**: MAC addresses, EtherType (numeric + name), VLAN
- **Layer 3 (IPv4/IPv6)**: All IP header fields (TTL, ToS, flags, checksums, etc.)
- **Layer 4 (TCP/UDP/ICMP)**: All transport header fields (seq/ack, windows, flags, etc.)

### 2. Wireshark-Style Multi-Line Descriptions
The `description` field provides a multi-line, human-readable breakdown similar to Wireshark:

```
Frame: Packet, 66 bytes on wire (528 bits), 66 bytes captured (528 bits)
Ethernet II, Src: 02:00:00:00:00:0f (02:00:00:00:00:0f), Dst: 02:00:00:00:00:1a (02:00:00:00:00:1a)
Internet Protocol Version 4, Src: 10.0.0.26, Dst: 8.8.8.8
User Datagram Protocol, Src Port: 53000, Dst Port: 53
Domain Name System (query)
```

## Quick Start

### Build the WASM Module
```bash
cd crates/protocol-wasm
wasm-pack build --target web
```

### Test in Node.js
```bash
node test-decoder.mjs
```

### Use in Browser/Frontend
```typescript
import { decodePacket } from './lib/decoders'

const decoded = decodePacket(packet)

// Get Wireshark-style description
console.log(decoded.description)

// Access individual fields
console.log('TTL:', decoded.l3?.ttl)
console.log('TCP Seq:', decoded.l4?.tcpSeq)
console.log('Window Size:', decoded.l4?.tcpWindow)
```

## Return Structure

```typescript
{
  l2?: {
    srcMac: string              // "02:00:00:00:00:0f"
    dstMac: string
    etherType: number           // 0x0800
    etherTypeName: string       // "IPv4"
    vlan?: number
  }
  l3?: {
    proto: string               // "IPv4" | "IPv6" | "ARP"
    src: string                 // "10.0.0.26"
    dst: string
    // IPv4 specific
    version: number             // 4
    headerLen: number           // 5 (in 32-bit words)
    tos: number
    totalLen: number            // 66
    identification: number
    flags: number
    fragmentOffset: number
    ttl: number                 // 64
    protocol: number            // 17 (UDP)
    checksum: number
    // IPv6 specific
    trafficClass?: number
    flowLabel?: number
    payloadLen?: number
    nextHeader?: number
    hopLimit?: number
  }
  l4?: {
    proto: string               // "TCP" | "UDP" | "ICMP"
    srcPort: number             // 53000
    dstPort: number             // 53
    // TCP specific
    tcpFlags?: string           // "SYN,ACK"
    tcpSeq?: number
    tcpAck?: number
    tcpWindow?: number
    tcpChecksum?: number
    tcpUrgent?: number
    tcpDataOffset?: number
    // UDP specific
    udpLen?: number             // 46
    udpChecksum?: number
    // ICMP specific
    icmpType?: number
    icmpCode?: number
    icmpChecksum?: number
  }
  summary: string               // "UDP 53000 → 53"
  protocolTag: string           // "UDP"
  appTag?: string              // "DNS"
  description: string           // Multi-line Wireshark-style text
}
```

## Example Output

### DNS Query Packet
```
Frame: Packet, 71 bytes on wire (568 bits), 71 bytes captured (568 bits)
Ethernet II, Src: 02:00:00:00:00:0f (02:00:00:00:00:0f), Dst: 02:00:00:00:00:1a (02:00:00:00:00:1a)
Internet Protocol Version 4, Src: 10.0.0.26, Dst: 8.8.8.8
User Datagram Protocol, Src Port: 52984, Dst Port: 53
Domain Name System (query)
```

### TCP SYN Packet
```
Frame: Packet, 54 bytes on wire (432 bits), 54 bytes captured (432 bits)
Ethernet II, Src: aa:bb:cc:dd:ee:ff (aa:bb:cc:dd:ee:ff), Dst: ff:ff:ff:ff:ff:ff (ff:ff:ff:ff:ff:ff)
Internet Protocol Version 4, Src: 192.168.1.100, Dst: 95.183.245.78
Transmission Control Protocol, Src Port: 50000, Dst Port: 80
```

### ICMP Packet
```
Frame: Packet, 42 bytes on wire (336 bits), 42 bytes captured (336 bits)
Ethernet II, Src: aa:bb:cc:dd:ee:ff (aa:bb:cc:dd:ee:ff), Dst: 00:11:22:33:44:55 (00:11:22:33:44:55)
Internet Protocol Version 4, Src: 192.168.1.10, Dst: 8.8.8.8
Internet Control Message Protocol, Type: 8, Code: 0
```

## Documentation

- **PACKET_HEADERS.md** - Complete field reference
- **DESCRIPTION_FORMAT.md** - Multi-line description format and usage examples
- **test-decoder.mjs** - Node.js test script
- **test-description.html** - Browser test page

## Usage in UI Components

### React
```tsx
function PacketDetails({ packet }: { packet: ParsedPacket }) {
  const decoded = decodePacket(packet)
  
  return (
    <div className="packet-info">
      {decoded.description?.split('\n').map((line, i) => (
        <div key={i} className="protocol-line">{line}</div>
      ))}
    </div>
  )
}
```

### Svelte
```svelte
<script>
  export let packet
  $: decoded = decodePacket(packet)
</script>

<div class="packet-info">
  {#each decoded.description?.split('\n') || [] as line}
    <div class="protocol-line">{line}</div>
  {/each}
</div>
```

### Plain JavaScript
```javascript
const decoded = decodePacket(packet)
element.textContent = decoded.description
```

## Protocol Detection

The decoder automatically detects and labels:

- **Transport**: TCP, UDP, ICMP
- **Application** (by port): DNS (53), HTTP (80), HTTPS (443), etc.

## Performance

- All decoding happens in WASM (very fast)
- Zero-copy operations where possible
- Minimal memory allocations
- Suitable for real-time packet analysis

## Future Enhancements

- [ ] IPv6 support in descriptions
- [ ] More detailed TCP flag descriptions
- [ ] Application protocol payload parsing
- [ ] Protocol anomaly detection
- [ ] Configurable description format
