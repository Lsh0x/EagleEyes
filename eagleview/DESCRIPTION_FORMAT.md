# Packet Description Format

The WASM decoder now generates **multi-line Wireshark-style descriptions** for each packet.

## Format

The `description` field contains a newline-separated string with protocol information at each layer:

```
Frame: Packet, <bytes> bytes on wire (<bits> bits), <bytes> bytes captured (<bits> bits)
Ethernet II, Src: <mac> (<mac>), Dst: <mac> (<mac>)[, VLAN: <vlan>]
Internet Protocol Version <version>, Src: <ip>, Dst: <ip>
<Transport Protocol>, Src Port: <port>, Dst Port: <port>
[Application Protocol]
```

## Real Examples

### DNS Query Packet
```
Frame: Packet, 66 bytes on wire (528 bits), 66 bytes captured (528 bits)
Ethernet II, Src: 02:00:00:00:00:0f (02:00:00:00:00:0f), Dst: 02:00:00:00:00:1a (02:00:00:00:00:1a)
Internet Protocol Version 4, Src: 10.0.0.26, Dst: 8.8.8.8
User Datagram Protocol, Src Port: 53000, Dst Port: 53
Domain Name System (query)
```

### TCP SYN Packet
```
Frame: Packet, 54 bytes on wire (432 bits), 54 bytes captured (432 bits)
Ethernet II, Src: aa:bb:cc:dd:ee:ff (aa:bb:cc:dd:ee:ff), Dst: ff:ff:ff:ff:ff:ff (ff:ff:ff:ff:ff:ff)
Internet Protocol Version 4, Src: 192.168.1.100, Dst: 95.183.245.78
Transmission Control Protocol, Src Port: 50000, Dst Port: 80
```

### ICMP Echo Request
```
Frame: Packet, 42 bytes on wire (336 bits), 42 bytes captured (336 bits)
Ethernet II, Src: aa:bb:cc:dd:ee:ff (aa:bb:cc:dd:ee:ff), Dst: 00:11:22:33:44:55 (00:11:22:33:44:55)
Internet Protocol Version 4, Src: 192.168.1.10, Dst: 8.8.8.8
Internet Control Message Protocol, Type: 8, Code: 0
```

### VLAN Tagged Packet
```
Frame: Packet, 70 bytes on wire (560 bits), 70 bytes captured (560 bits)
Ethernet II, Src: 02:00:00:00:00:0f (02:00:00:00:00:0f), Dst: 02:00:00:00:00:1a (02:00:00:00:00:1a), VLAN: 100
Internet Protocol Version 4, Src: 10.0.0.26, Dst: 8.8.8.8
User Datagram Protocol, Src Port: 53000, Dst Port: 53
Domain Name System (query)
```

## Usage in Code

### TypeScript/JavaScript
```typescript
import { decodePacket } from './lib/decoders'

const decoded = decodePacket(packet)

// Get the multi-line description
if (decoded.description) {
  // Display in UI
  element.textContent = decoded.description
  
  // Or split into lines
  const lines = decoded.description.split('\n')
  lines.forEach(line => {
    console.log(line)
  })
}
```

### React Component Example
```tsx
function PacketDetails({ packet }: { packet: ParsedPacket }) {
  const decoded = decodePacket(packet)
  
  return (
    <div className="packet-details">
      {decoded.description?.split('\n').map((line, i) => (
        <div key={i} className="protocol-line">
          {line}
        </div>
      ))}
    </div>
  )
}
```

### Svelte Component Example
```svelte
<script>
  import { decodePacket } from './lib/decoders'
  
  export let packet
  $: decoded = decodePacket(packet)
  $: lines = decoded.description?.split('\n') || []
</script>

<div class="packet-details">
  {#each lines as line}
    <div class="protocol-line">{line}</div>
  {/each}
</div>
```

## Styling Recommendations

### CSS for Wireshark-like Display
```css
.packet-details {
  font-family: 'Courier New', monospace;
  font-size: 13px;
  line-height: 1.6;
  background: #f5f5f5;
  padding: 12px;
  border-left: 3px solid #007acc;
}

.protocol-line {
  margin: 2px 0;
  white-space: pre-wrap;
}

.protocol-line:first-child {
  font-weight: bold;
  color: #333;
}
```

### With Color Coding by Layer
```css
.protocol-line:nth-child(1) { color: #666; }      /* Frame */
.protocol-line:nth-child(2) { color: #0066cc; }   /* Ethernet */
.protocol-line:nth-child(3) { color: #009900; }   /* IP */
.protocol-line:nth-child(4) { color: #cc6600; }   /* Transport */
.protocol-line:nth-child(5) { color: #9900cc; }   /* Application */
```

## Protocol Detection

The description automatically detects and labels:

### Transport Protocols
- TCP: "Transmission Control Protocol"
- UDP: "User Datagram Protocol"
- ICMP: "Internet Control Message Protocol"

### Application Protocols (by port)
- Port 53: "Domain Name System (query)"
- Port 80/443: HTTP/HTTPS
- Port 22: SSH
- etc.

## Advanced Features

### Accessing Both Description and Fields
```typescript
const decoded = decodePacket(packet)

// Use description for display
console.log(decoded.description)

// Use individual fields for filtering/analysis
if (decoded.l3?.ttl && decoded.l3.ttl < 10) {
  console.warn('Low TTL detected:', decoded.l3.ttl)
}

if (decoded.l4?.tcpSeq) {
  console.log('TCP Sequence:', decoded.l4.tcpSeq)
}
```

### Building Custom Descriptions
```typescript
function customDescription(decoded: Decoded): string {
  const lines = []
  
  // Start with the built-in description
  if (decoded.description) {
    lines.push(...decoded.description.split('\n'))
  }
  
  // Add custom analysis
  if (decoded.l3?.ttl && decoded.l3.ttl < 10) {
    lines.push('[Analysis] Low TTL - packet may be expiring soon')
  }
  
  if (decoded.l4?.tcpFlags?.includes('RST')) {
    lines.push('[Analysis] Connection reset detected')
  }
  
  return lines.join('\n')
}
```

## Notes

- The description is generated in real-time by the WASM decoder
- All descriptions follow a consistent format for easy parsing
- Lines are ordered from lowest (physical) to highest (application) layer
- DNS detection is based on port 53 (standard DNS port)
- Future versions may include more detailed application protocol parsing
