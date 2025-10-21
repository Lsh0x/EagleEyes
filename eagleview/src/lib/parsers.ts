/* Minimal PCAP and PCAPNG parsers for browser use. */

export type ParsedPacket = {
  ts: number | null // epoch seconds
  capturedLen: number
  originalLen: number
  ifIndex?: number
  data: Uint8Array
}

export type ParsedCapture = {
  format: 'pcap' | 'pcapng'
  packets: ParsedPacket[]
}

export function parseCapture(buf: ArrayBuffer): ParsedCapture {
  const u8 = new Uint8Array(buf)
  if (u8.byteLength < 4) throw new Error('File too small')
  const m0 = u8[0], m1 = u8[1], m2 = u8[2], m3 = u8[3]
  // PCAPNG SHB block type (palindrome) = 0x0A0D0D0A
  if (m0 === 0x0a && m1 === 0x0d && m2 === 0x0d && m3 === 0x0a) {
    return parsePcapng(buf)
  }
  // PCAP magic numbers
  const isPcapBE = m0 === 0xa1 && m1 === 0xb2 && m2 === 0xc3 && m3 === 0xd4
  const isPcapLE = m0 === 0xd4 && m1 === 0xc3 && m2 === 0xb2 && m3 === 0xa1
  const isPcapNsecBE = m0 === 0xa1 && m1 === 0xb2 && m2 === 0x3c && m3 === 0x4d
  const isPcapNsecLE = m0 === 0x4d && m1 === 0x3c && m2 === 0xb2 && m3 === 0xa1
  if (isPcapBE || isPcapLE || isPcapNsecBE || isPcapNsecLE) {
    return parsePcap(buf)
  }
  throw new Error('Unrecognized capture format (pcap/pcapng)')
}

function parsePcap(buf: ArrayBuffer): ParsedCapture {
  const dv = new DataView(buf)
  const u8 = new Uint8Array(buf)
  const b0 = dv.getUint8(0), b1 = dv.getUint8(1), b2 = dv.getUint8(2), b3 = dv.getUint8(3)
  const isLE = (b0 === 0xd4 && b1 === 0xc3 && b2 === 0xb2 && b3 === 0xa1) ||
               (b0 === 0x4d && b1 === 0x3c && b2 === 0xb2 && b3 === 0xa1)
  const isNsec = (b0 === 0xa1 && b1 === 0xb2 && b2 === 0x3c && b3 === 0x4d) ||
                 (b0 === 0x4d && b1 === 0x3c && b2 === 0xb2 && b3 === 0xa1)
  let off = 24 // global header
  const packets: ParsedPacket[] = []
  while (off + 16 <= dv.byteLength) {
    const tsSec = dv.getUint32(off + 0, isLE)
    const tsFrac = dv.getUint32(off + 4, isLE)
    const inclLen = dv.getUint32(off + 8, isLE)
    const origLen = dv.getUint32(off + 12, isLE)
    off += 16
    if (off + inclLen > dv.byteLength) break
    const ts = tsSec + tsFrac / (isNsec ? 1e9 : 1e6)
    const data = u8.subarray(off, off + inclLen)
    packets.push({ ts, capturedLen: inclLen, originalLen: origLen, data })
    off += inclLen
  }
  return { format: 'pcap', packets }
}

function parsePcapng(buf: ArrayBuffer): ParsedCapture {
  const dv = new DataView(buf)
  const u8 = new Uint8Array(buf)
  const len = dv.byteLength
  let off = 0
  let le = true // will be updated after SHB
  const tsresByIf: Record<number, number> = {} // seconds per tick
  let currentSectionLE: boolean | null = null

  const packets: ParsedPacket[] = []

  while (off + 12 <= len) {
    // Read block type with any endianness (SHB type is palindromic)
    const blockType = dv.getUint32(off, true)
    const blockTypeBE = dv.getUint32(off, false)
    if (blockType !== blockTypeBE) {
      // For non-SHB later we must honor currentSectionLE
    }
    const totalLenLE = dv.getUint32(off + 4, le)
    let totalLen = totalLenLE

    if (blockType === 0x0a0d0d0a) {
      // Section Header Block
      const b0 = dv.getUint8(off + 8)
      const b1 = dv.getUint8(off + 9)
      const b2 = dv.getUint8(off + 10)
      const b3 = dv.getUint8(off + 11)
      if (b0 === 0x1a && b1 === 0x2b && b2 === 0x3c && b3 === 0x4d) {
        le = false // big-endian section
      } else if (b0 === 0x4d && b1 === 0x3c && b2 === 0x2b && b3 === 0x1a) {
        le = true // little-endian section
      } else {
        // Try decide by comparing total length fields
        le = totalLenLE === dv.getUint32(off + (totalLenLE - 4), true)
      }
      currentSectionLE = le
      totalLen = dv.getUint32(off + 4, le)
      if (totalLen < 12) break
      off += totalLen
      continue
    }

    // From here, we must have determined section endianness
    if (currentSectionLE == null) {
      // If no SHB seen, bail out
      break
    }
    le = currentSectionLE
    totalLen = dv.getUint32(off + 4, le)
    if (totalLen < 12 || off + totalLen > len) break

    switch (blockType) {
      case 0x00000001: { // Interface Description Block (IDB)
        // LinkType:16, Reserved:16, SnapLen:32
        const ifIndex = Object.keys(tsresByIf).length
        // Default: microsecond resolution
        tsresByIf[ifIndex] = 1e-6
        // Parse options to find if_tsresol (code 9)
        const bodyStart = off + 8
        const optionsStart = bodyStart + 8
        let optOff = optionsStart
        const end = off + totalLen - 4
        while (optOff + 4 <= end) {
          const optCode = dv.getUint16(optOff + 0, le)
          const optLen = dv.getUint16(optOff + 2, le)
          optOff += 4
          if (optCode === 0) break // end
          if (optOff + optLen > end) break
          if (optCode === 9 && optLen >= 1) {
            const v = dv.getUint8(optOff)
            if (v & 0x80) {
              // Most significant bit set => resolution = 2^-(v & 0x7F)
              const p = v & 0x7f
              tsresByIf[ifIndex] = 1 / Math.pow(2, p)
            } else {
              // decimal: 10^-v
              tsresByIf[ifIndex] = 1 / Math.pow(10, v)
            }
          }
          // options are padded to 32-bit
          const pad = (4 - (optLen % 4)) % 4
          optOff += optLen + pad
        }
        break
      }
      case 0x00000006: { // Enhanced Packet Block (EPB)
        const ifId = dv.getUint32(off + 8, le)
        const tsHigh = dv.getUint32(off + 12, le)
        const tsLow = dv.getUint32(off + 16, le)
        const capLen = dv.getUint32(off + 20, le)
        const origLen = dv.getUint32(off + 24, le)
        const dataStart = off + 28
        const data = u8.subarray(dataStart, dataStart + capLen)
        const tsTicks = tsToBigInt(tsHigh, tsLow)
        const res = tsresByIf[ifId] ?? 1e-6
        const ts = Number(tsTicks) * res
        packets.push({ ts, capturedLen: capLen, originalLen: origLen, ifIndex: ifId, data })
        break
      }
      case 0x00000003: { // Simple Packet Block
        const origLen = dv.getUint32(off + 8, le)
        // In SPB, captured length = totalLen - 16 (two length fields + type + header fields)
        const capLen = (dv.getUint32(off + 4, le)) - 16
        const dataStart = off + 12
        const data = u8.subarray(dataStart, dataStart + Math.max(0, capLen))
        packets.push({ ts: null, capturedLen: Math.max(0, capLen), originalLen: origLen, data })
        break
      }
      default:
        // ignore other blocks
        break
    }

    off += totalLen
  }

  return { format: 'pcapng', packets }
}

function tsToBigInt(high: number, low: number): bigint {
  return (BigInt(high) << 32n) | BigInt(low >>> 0)
}