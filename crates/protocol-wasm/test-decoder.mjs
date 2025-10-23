#!/usr/bin/env node

import { readFile } from 'fs/promises';
import { fileURLToPath } from 'url';
import { dirname, join } from 'path';
import init, { decode_packet } from './pkg/protocol_wasm.js';

const __dirname = dirname(fileURLToPath(import.meta.url));
const wasmPath = join(__dirname, 'pkg', 'protocol_wasm_bg.wasm');
const wasmBytes = await readFile(wasmPath);
await init(wasmBytes);

// DNS query packet matching the example from the screenshot
const dnsPacket = new Uint8Array([
    // Ethernet header (14 bytes)
    0x02, 0x00, 0x00, 0x00, 0x00, 0x1a,  // dst MAC: 02:00:00:00:00:1a
    0x02, 0x00, 0x00, 0x00, 0x00, 0x0f,  // src MAC: 02:00:00:00:00:0f (matches screenshot)
    0x08, 0x00,                          // EtherType: IPv4
    
    // IPv4 header (20 bytes)
    0x45,                                // Version 4, IHL 5
    0x00,                                // ToS
    0x00, 0x42,                          // Total Length: 66 bytes (matches screenshot)
    0x12, 0x34,                          // Identification
    0x40, 0x00,                          // Flags (DF), Fragment offset
    0x40,                                // TTL: 64
    0x11,                                // Protocol: UDP (17)
    0x00, 0x00,                          // Checksum
    0x0a, 0x00, 0x00, 0x1a,              // Source IP: 10.0.0.26 (matches screenshot)
    0x08, 0x08, 0x08, 0x08,              // Dest IP: 8.8.8.8 (matches screenshot)
    
    // UDP header (8 bytes)
    0xce, 0xf8,                          // Source port: 53000 (matches screenshot)
    0x00, 0x35,                          // Dest port: 53 (DNS - matches screenshot)
    0x00, 0x2e,                          // Length: 46
    0x00, 0x00,                          // Checksum
    
    // DNS payload (38 bytes minimum)
    0x00, 0x01,                          // Transaction ID
    0x01, 0x00,                          // Flags: standard query
    0x00, 0x01,                          // Questions: 1
    0x00, 0x00,                          // Answer RRs
    0x00, 0x00,                          // Authority RRs
    0x00, 0x00,                          // Additional RRs
    // Query
    0x07, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65,  // "example"
    0x03, 0x63, 0x6f, 0x6d,                          // "com"
    0x00,                                            // null
    0x00, 0x01,                          // Type: A
    0x00, 0x01,                          // Class: IN
]);

console.log('Testing WASM Packet Decoder\n');
console.log('Packet size:', dnsPacket.length, 'bytes\n');

try {
    const result = decode_packet(dnsPacket);
    
    console.log('=== WIRESHARK-STYLE DESCRIPTION ===');
    if (result.description) {
        console.log(result.description);
    } else {
        console.log('No description available');
    }
    
    console.log('\n=== DECODED FIELDS ===');
    console.log('Summary:', result.summary);
    console.log('Protocol Tag:', result.protocolTag);
    
    if (result.l2) {
        console.log('\nLayer 2 (Ethernet):');
        console.log('  Source MAC:', result.l2.srcMac);
        console.log('  Dest MAC:', result.l2.dstMac);
        console.log('  EtherType:', `0x${result.l2.etherType?.toString(16).padStart(4, '0')} (${result.l2.etherTypeName})`);
    }
    
    if (result.l3) {
        console.log('\nLayer 3 (IP):');
        console.log('  Protocol:', result.l3.proto);
        console.log('  Source IP:', result.l3.src);
        console.log('  Dest IP:', result.l3.dst);
        console.log('  Version:', result.l3.version);
        console.log('  TTL:', result.l3.ttl);
        console.log('  Total Length:', result.l3.totalLen);
        console.log('  Protocol Number:', result.l3.protocol);
    }
    
    if (result.l4) {
        console.log('\nLayer 4 (Transport):');
        console.log('  Protocol:', result.l4.proto);
        console.log('  Source Port:', result.l4.srcPort);
        console.log('  Dest Port:', result.l4.dstPort);
        if (result.l4.udpLen) {
            console.log('  UDP Length:', result.l4.udpLen);
            console.log('  UDP Checksum:', `0x${result.l4.udpChecksum?.toString(16).padStart(4, '0')}`);
        }
    }
    
    console.log('\n✓ Decoding successful!');
    
} catch (e) {
    console.error('Error decoding packet:', e.message);
    process.exit(1);
}
