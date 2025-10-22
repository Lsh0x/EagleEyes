import type { ParsedPacket } from './parsers'

export type Decoded = {
  l2?: {
    srcMac?: string
    dstMac?: string
    etherType?: number
    vlan?: number
  }
  l3?: {
    proto?: 'IPv4' | 'IPv6' | 'ARP'
    src?: string
    dst?: string
  }
  l4?: {
    proto?: 'TCP' | 'UDP' | 'ICMPv4' | 'ICMPv6'
    srcPort?: number
    dstPort?: number
    tcpFlags?: string
  }
  summary: string
  protocolTag: string
  meta?: {
    arp?: { op?: number; spa?: string; tpa?: string }
    dns?: { id: number; qr: boolean; name?: string; qtype?: number; qtypeName?: string }
    tcp?: { flags: number }
  }
}

export function decodePacket(p: ParsedPacket): Decoded {
  const d: Decoded = { summary: '', protocolTag: '' }
  const u = p.data
  if (u.length < 14) return { ...d, summary: `Truncated frame (${u.length}B)`, protocolTag: 'FRAME' }

  // Ethernet II
  const dst = macToStr(u.subarray(0, 6))
  const src = macToStr(u.subarray(6, 12))
  let etherType = (u[12] << 8) | u[13]
  let off = 14
  let vlan: number | undefined
  if (etherType === 0x8100 && u.length >= 18) { // 802.1Q VLAN tag
    const tci = (u[14] << 8) | u[15]
    vlan = tci & 0x0fff
    etherType = (u[16] << 8) | u[17]
    off = 18
  }
  const l2 = { srcMac: src, dstMac: dst, etherType, vlan }

  // L3
  if (etherType === 0x0800 && u.length >= off + 20) { // IPv4
    const ihl = (u[off] & 0x0f) * 4
    if (ihl < 20 || u.length < off + ihl) return finalize('IPv4 (bad header)')
    const proto = u[off + 9]
    const srcIp = ipv4ToStr(u, off + 12)
    const dstIp = ipv4ToStr(u, off + 16)
    const l3 = { proto: 'IPv4' as const, src: srcIp, dst: dstIp }
    let l4 = decodeL4(u, off + ihl, proto)
    return finalize(l4.summary, { l2, l3, l4, tag: l4.tag })
  }
  if (etherType === 0x86dd && u.length >= off + 40) { // IPv6
    const next = u[off + 6]
    const srcIp = ipv6ToStr(u, off + 8)
    const dstIp = ipv6ToStr(u, off + 24)
    const l3 = { proto: 'IPv6' as const, src: srcIp, dst: dstIp }
    let l4 = decodeL4(u, off + 40, next, true)
    return finalize(l4.summary, { l2, l3, l4, tag: l4.tag })
  }
  if (etherType === 0x0806 && u.length >= off + 28) { // ARP IPv4
    const op = (u[off + 6] << 8) | u[off + 7]
    const spa = ipv4ToStr(u, off + 14)
    const tpa = ipv4ToStr(u, off + 24)
    const summary = op === 1 ? `ARP Who has ${tpa}? Tell ${spa}` : op === 2 ? `ARP Reply ${spa} is-at ${macToStr(u.subarray(off + 8, off + 14))}` : 'ARP'
    return finalize(summary, { l2, l3: { proto: 'ARP', src: spa, dst: tpa }, tag: 'ARP', meta: { arp: { op, spa, tpa } } })
  }
  if (etherType === 0x88cc) { // LLDP
    return finalize('LLDP', { l2, tag: 'LLDP' })
  }
  if (etherType === 0x8847 || etherType === 0x8848) { // MPLS
    return finalize('MPLS', { l2, tag: 'MPLS' })
  }
  if (etherType === 0x8863 || etherType === 0x8864) { // PPPoE
    return finalize(etherType === 0x8863 ? 'PPPoE Discovery' : 'PPPoE Session', { l2, tag: 'PPPoE' })
  }
  if (etherType <= 1500) { // IEEE 802.3 LLC/SNAP
    const dsap = u[off]; const ssap = u[off+1]; const ctrl = u[off+2]
    if (dsap === 0xaa && ssap === 0xaa && ctrl === 0x03 && u.length >= off + 8) {
      const oui = (u[off+3] << 16) | (u[off+4] << 8) | u[off+5]
      const pid = (u[off+6] << 8) | u[off+7]
      if (oui === 0x00000c && pid === 0x2000) return finalize('CDP', { l2, tag: 'CDP' })
      return finalize('SNAP', { l2, tag: 'LLC' })
    }
    if (dsap === 0x42 && ssap === 0x42) return finalize('STP BPDU', { l2, tag: 'STP' })
    return finalize('802.3 LLC', { l2, tag: 'LLC' })
  }

  return finalize(etherType ? `Ethertype 0x${etherType.toString(16)}` : 'Frame', { l2, tag: 'ETH' })

  function finalize(summary: string, extra?: { l2?: any; l3?: any; l4?: any; tag?: string; meta?: Decoded['meta'] }) {
    return {
      l2: extra?.l2 ?? l2,
      l3: extra?.l3,
      l4: extra?.l4,
      summary,
      protocolTag: extra?.tag || (extra?.l4?.proto || extra?.l3?.proto || 'ETH'),
      meta: extra?.meta,
    } as Decoded
  }
}

function decodeL4(u: Uint8Array, off: number, proto: number, isv6 = false): { l4: Decoded['l4']; summary: string; tag: string; meta?: Decoded['meta'] } {
  if (proto === 6 && u.length >= off + 20) { // TCP
    const srcPort = (u[off] << 8) | u[off + 1]
    const dstPort = (u[off + 2] << 8) | u[off + 3]
    const flagsByte = u[off + 13]
    const flags = tcpFlags(flagsByte)
    if (srcPort === 179 || dstPort === 179) {
      return { l4: { proto: 'TCP', srcPort, dstPort, tcpFlags: flags }, summary: 'BGP', tag: 'BGP', meta: { tcp: { flags: flagsByte } } }
    }
    const info = `${srcPort} → ${dstPort} [${flags}]`
    const tag = 'TCP'
    return { l4: { proto: 'TCP', srcPort, dstPort, tcpFlags: flags }, summary: info, tag, meta: { tcp: { flags: flagsByte } } }
  }
  if (proto === 17 && u.length >= off + 8) { // UDP
    const srcPort = (u[off] << 8) | u[off + 1]
    const dstPort = (u[off + 2] << 8) | u[off + 3]
    const dns = srcPort === 53 || dstPort === 53 ? decodeDns(u, off + 8) : undefined
    const info = dns ? `DNS ${dns.summary}` : `${srcPort} → ${dstPort}`
    const tag = dns ? 'DNS' : 'UDP'
    return { l4: { proto: 'UDP', srcPort, dstPort }, summary: info, tag, meta: dns ? { dns: { id: dns.id!, qr: dns.qr, name: dns.name, qtype: dns.qtype, qtypeName: dns.qtypeName } } : undefined }
  }
  if ((proto === 1 && !isv6) || (proto === 58 && isv6)) { // ICMPv4/ICMPv6
    const type = u[off]
    const code = u[off + 1]
    const which = isv6 ? 'ICMPv6' : 'ICMPv4'
    return { l4: { proto: which as any }, summary: `${which} type ${type} code ${code}`, tag: which }
  }
  const protoName = isv6 ? ipv6NextHeaderToName(proto) : ipv4ProtoToName(proto)
  return { l4: { proto: undefined }, summary: protoName, tag: protoName }
}

function macToStr(u: Uint8Array): string {
  return Array.from(u).map(b => b.toString(16).padStart(2, '0')).join(':')
}
function ipv4ToStr(u: Uint8Array, off: number): string {
  return `${u[off]}.${u[off+1]}.${u[off+2]}.${u[off+3]}`
}
function ipv6ToStr(u: Uint8Array, off: number): string {
  const parts: string[] = []
  for (let i = 0; i < 16; i += 2) parts.push(((u[off + i] << 8) | u[off + i + 1]).toString(16))
  // naive compress
  return parts.join(':').replace(/(^|:)0(:0)+(:|$)/, '::')
}
function tcpFlags(b: number): string {
  const flags = [
    (b & 0x01) ? 'FIN' : '',
    (b & 0x02) ? 'SYN' : '',
    (b & 0x04) ? 'RST' : '',
    (b & 0x08) ? 'PSH' : '',
    (b & 0x10) ? 'ACK' : '',
    (b & 0x20) ? 'URG' : '',
    (b & 0x40) ? 'ECE' : '',
    (b & 0x80) ? 'CWR' : '',
  ].filter(Boolean)
  return flags.join(',') || 'NONE'
}
function ipv4ProtoToName(p: number): string {
  const m: Record<number,string> = {1:'ICMP',2:'IGMP',6:'TCP',17:'UDP',47:'GRE',50:'ESP',51:'AH',88:'EIGRP',89:'OSPF'}
  return m[p] || `Proto ${p}`
}
function ipv6NextHeaderToName(p: number): string {
  const m: Record<number,string> = {58:'ICMPv6',6:'TCP',17:'UDP'}
  return m[p] || `NH ${p}`
}

function decodeDns(u: Uint8Array, off: number): { summary: string; id?: number; qr: boolean; name?: string; qtype?: number; qtypeName?: string } | undefined {
  if (u.length < off + 12) return undefined
  const id = (u[off + 0] << 8) | u[off + 1]
  const flags = (u[off + 2] << 8) | u[off + 3]
  const qd = (u[off + 4] << 8) | u[off + 5]
  const qr = (flags & 0x8000) !== 0
  let p = off + 12
  let name = ''
  let qtype: number | undefined
  try {
    if (qd > 0) {
      const dn = readDnsNameWithPtr(u, p, off)
      name = dn.name
      p = dn.next
      if (u.length >= p + 4) {
        qtype = (u[p] << 8) | u[p + 1]
        // const qclass = (u[p + 2] << 8) | u[p + 3]
      }
    }
  } catch {}
  const qtypeName = qtypeToStr(qtype)
  const summary = qr ? `response${name ? ' for ' + name : ''}` : (name ? `query ${name}${qtypeName ? ' ' + qtypeName : ''}` : 'query')
  return { summary, id, qr, name, qtype, qtypeName }
}
function readDnsNameWithPtr(u: Uint8Array, pos: number, base: number): { name: string; next: number } {
  const labels: string[] = []
  let p = pos
  let jumped = false
  let next = pos
  for (let i=0;i<128;i++) {
    if (p >= u.length) break
    const len = u[p]
    if (len === 0) { if (!jumped) next = p + 1; break }
    if ((len & 0xc0) === 0xc0) {
      const ptr = ((len & 0x3f) << 8) | u[p+1]
      if (!jumped) next = p + 2
      p = base + ptr
      jumped = true
      continue
    }
    p++
    const label = new TextDecoder().decode(u.subarray(p, p + len))
    labels.push(label)
    p += len
  }
  return { name: labels.join('.'), next }
}
function qtypeToStr(t?: number): string {
  const m: Record<number,string> = {1:'A',28:'AAAA',5:'CNAME',12:'PTR',15:'MX',16:'TXT',6:'SOA',33:'SRV',35:'NAPTR'}
  return t && m[t] ? m[t] : (t ? `TYPE${t}` : '')
}

// Best-effort extraction of L4 payload (TCP/UDP) from an Ethernet frame
export function extractL4Payload(u: Uint8Array): { proto: 'TCP' | 'UDP' | 'OTHER'; offset: number; length: number } | null {
  if (u.length < 14) return null
  let etherType = (u[12] << 8) | u[13]
  let off = 14
  if (etherType === 0x8100 && u.length >= 18) {
    etherType = (u[16] << 8) | u[17]
    off = 18
  }
  if (etherType === 0x0800) { // IPv4
    if (u.length < off + 20) return null
    const ihl = (u[off] & 0x0f) * 4
    if (ihl < 20 || u.length < off + ihl) return null
    const proto = u[off + 9]
    const l4 = off + ihl
    if (proto === 6) { // TCP
      if (u.length < l4 + 20) return null
      const dataOffset = (u[l4 + 12] >> 4) * 4
      const start = l4 + dataOffset
      const length = Math.max(0, u.length - start)
      return { proto: 'TCP', offset: start, length }
    }
    if (proto === 17) { // UDP
      if (u.length < l4 + 8) return null
      const start = l4 + 8
      const length = Math.max(0, u.length - start)
      return { proto: 'UDP', offset: start, length }
    }
    return { proto: 'OTHER', offset: l4, length: Math.max(0, u.length - l4) }
  }
  if (etherType === 0x86dd) { // IPv6 (ignore ext headers)
    const l4 = off + 40
    if (u.length < l4) return null
    const next = u[off + 6]
    if (next === 6) { // TCP
      if (u.length < l4 + 20) return null
      const dataOffset = (u[l4 + 12] >> 4) * 4
      const start = l4 + dataOffset
      const length = Math.max(0, u.length - start)
      return { proto: 'TCP', offset: start, length }
    }
    if (next === 17) { // UDP
      if (u.length < l4 + 8) return null
      const start = l4 + 8
      const length = Math.max(0, u.length - start)
      return { proto: 'UDP', offset: start, length }
    }
    return { proto: 'OTHER', offset: l4, length: Math.max(0, u.length - l4) }
  }
  return null
}
