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
  appTag?: string
  meta?: {
    arp?: { op?: number; spa?: string; tpa?: string }
    dns?: { id: number; qr: boolean; name?: string; qtype?: number; qtypeName?: string }
    tcp?: { flags: number }
  }
}

// Use WASM decoder (protocol-wasm) when available; Vite will bundle it.
// eslint-disable-next-line import/no-unresolved
import { decode_packet as wasmDecode } from 'protocol-wasm'

export function decodePacket(p: ParsedPacket): Decoded {
  if (wasmDecode) {
    try {
      const res = wasmDecode(p.data) as Decoded
      // Ensure minimal fields
      if (!res.summary) (res as any).summary = ''
      if (!res.protocolTag) (res as any).protocolTag = (res.l4?.proto || res.l3?.proto || 'ETH') as any
      return res
    } catch {}
  }
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

  function finalize(summary: string, extra?: { l2?: any; l3?: any; l4?: any; tag?: string; appTag?: string; meta?: Decoded['meta'] }) {
    return {
      l2: extra?.l2 ?? l2,
      l3: extra?.l3,
      l4: extra?.l4,
      summary,
      protocolTag: extra?.tag || (extra?.l4?.proto || extra?.l3?.proto || 'ETH'),
      appTag: extra?.appTag,
      meta: extra?.meta,
    } as Decoded
  }
}

function decodeL4(u: Uint8Array, off: number, proto: number, isv6 = false): { l4: Decoded['l4']; summary: string; tag: string; appTag?: string; meta?: Decoded['meta'] } {
  if (proto === 6 && u.length >= off + 20) { // TCP
    const srcPort = (u[off] << 8) | u[off + 1]
    const dstPort = (u[off + 2] << 8) | u[off + 3]
    const flagsByte = u[off + 13]
    const flags = tcpFlags(flagsByte)
    const dataOffset = (u[off + 12] >> 4) * 4
    const start = off + dataOffset
    const payload = start <= u.length ? u.subarray(start) : new Uint8Array(0)

    // Try to detect TLS first (common on 443/8443)
    const tls = sniffTlsClientHello(payload)
    if (tls) {
      const summary = `TLS ClientHello${tls.sni ? ' SNI=' + tls.sni : ''}`
      return { l4: { proto: 'TCP', srcPort, dstPort, tcpFlags: flags }, summary, tag: 'TLS', appTag: 'TLS', meta: { tcp: { flags: flagsByte } } }
    }

    // HTTP/1.x detection by start-line (independent of port)
    const http = sniffHttpStartLine(payload)
    if (http) {
      // Detect DoH from request line or headers
      let appTag: string | undefined = 'HTTP'
      if (http.type === 'request') {
        if (http.path && (http.path.includes('/dns-query') || http.path.toLowerCase().includes('doh'))) appTag = 'DOH'
        return { l4: { proto: 'TCP', srcPort, dstPort, tcpFlags: flags }, summary: `HTTP ${http.method} ${http.path}`, tag: 'HTTP', appTag, meta: { tcp: { flags: flagsByte } } }
      } else {
        return { l4: { proto: 'TCP', srcPort, dstPort, tcpFlags: flags }, summary: `HTTP ${http.status} ${http.text || ''}`.trim(), tag: 'HTTP', appTag, meta: { tcp: { flags: flagsByte } } }
      }
    }

    // STUN/TURN over TCP (RFC5389/5766)
    if (sniffStun(payload)) {
      const app = (srcPort === 3478 || dstPort === 3478) ? 'STUN/TURN' : 'STUN'
      return { l4: { proto: 'TCP', srcPort, dstPort, tcpFlags: flags }, summary: 'STUN', tag: 'TCP', appTag: app, meta: { tcp: { flags: flagsByte } } }
    }

    // Known port-based tags
    if (srcPort === 179 || dstPort === 179) return { l4: { proto: 'TCP', srcPort, dstPort, tcpFlags: flags }, summary: 'BGP', tag: 'BGP', appTag: 'BGP', meta: { tcp: { flags: flagsByte } } }
    if (srcPort === 22 || dstPort === 22) return { l4: { proto: 'TCP', srcPort, dstPort, tcpFlags: flags }, summary: 'SSH', tag: 'SSH', appTag: 'SSH', meta: { tcp: { flags: flagsByte } } }
    if (srcPort === 23 || dstPort === 23) return { l4: { proto: 'TCP', srcPort, dstPort, tcpFlags: flags }, summary: 'Telnet', tag: 'TELNET', appTag: 'TELNET', meta: { tcp: { flags: flagsByte } } }
    if (srcPort === 21 || dstPort === 21) return { l4: { proto: 'TCP', srcPort, dstPort, tcpFlags: flags }, summary: 'FTP', tag: 'FTP', appTag: 'FTP', meta: { tcp: { flags: flagsByte } } }
    if (srcPort === 990 || dstPort === 990) return { l4: { proto: 'TCP', srcPort, dstPort, tcpFlags: flags }, summary: 'FTPS', tag: 'FTPS', appTag: 'FTPS', meta: { tcp: { flags: flagsByte } } }
    if (srcPort === 25 || dstPort === 25 || srcPort === 587 || dstPort === 587) return { l4: { proto: 'TCP', srcPort, dstPort, tcpFlags: flags }, summary: 'SMTP', tag: 'SMTP', appTag: 'SMTP', meta: { tcp: { flags: flagsByte } } }
    if (srcPort === 465 || dstPort === 465) return { l4: { proto: 'TCP', srcPort, dstPort, tcpFlags: flags }, summary: 'SMTPS', tag: 'SMTPS', appTag: 'SMTPS', meta: { tcp: { flags: flagsByte } } }
    if (srcPort === 110 || dstPort === 110) return { l4: { proto: 'TCP', srcPort, dstPort, tcpFlags: flags }, summary: 'POP3', tag: 'POP3', appTag: 'POP3', meta: { tcp: { flags: flagsByte } } }
    if (srcPort === 143 || dstPort === 143) return { l4: { proto: 'TCP', srcPort, dstPort, tcpFlags: flags }, summary: 'IMAP', tag: 'IMAP', appTag: 'IMAP', meta: { tcp: { flags: flagsByte } } }
    if (srcPort === 993 || dstPort === 993) return { l4: { proto: 'TCP', srcPort, dstPort, tcpFlags: flags }, summary: 'IMAPS', tag: 'IMAPS', appTag: 'IMAPS', meta: { tcp: { flags: flagsByte } } }
    if (srcPort === 389 || dstPort === 389) return { l4: { proto: 'TCP', srcPort, dstPort, tcpFlags: flags }, summary: 'LDAP', tag: 'LDAP', appTag: 'LDAP', meta: { tcp: { flags: flagsByte } } }
    if (srcPort === 636 || dstPort === 636) return { l4: { proto: 'TCP', srcPort, dstPort, tcpFlags: flags }, summary: 'LDAPS', tag: 'LDAPS', appTag: 'LDAPS', meta: { tcp: { flags: flagsByte } } }
    if (srcPort === 139 || dstPort === 139 || srcPort === 445 || dstPort === 445) return { l4: { proto: 'TCP', srcPort, dstPort, tcpFlags: flags }, summary: 'SMB', tag: 'SMB', appTag: 'SMB', meta: { tcp: { flags: flagsByte } } }
    if (srcPort === 3389 || dstPort === 3389) return { l4: { proto: 'TCP', srcPort, dstPort, tcpFlags: flags }, summary: 'RDP', tag: 'RDP', appTag: 'RDP', meta: { tcp: { flags: flagsByte } } }
    if (srcPort === 554 || dstPort === 554) return { l4: { proto: 'TCP', srcPort, dstPort, tcpFlags: flags }, summary: 'RTSP', tag: 'RTSP', appTag: 'RTSP', meta: { tcp: { flags: flagsByte } } }
    if (srcPort === 5060 || dstPort === 5060) return { l4: { proto: 'TCP', srcPort, dstPort, tcpFlags: flags }, summary: 'SIP', tag: 'SIP', appTag: 'SIP', meta: { tcp: { flags: flagsByte } } }
    if (srcPort === 853 || dstPort === 853) return { l4: { proto: 'TCP', srcPort, dstPort, tcpFlags: flags }, summary: 'DNS over TLS', tag: 'TCP', appTag: 'DOT', meta: { tcp: { flags: flagsByte } } }
    if (srcPort === 6379 || dstPort === 6379) return { l4: { proto: 'TCP', srcPort, dstPort, tcpFlags: flags }, summary: 'Redis', tag: 'TCP', appTag: 'REDIS', meta: { tcp: { flags: flagsByte } } }
    if (srcPort === 1883 || dstPort === 1883) return { l4: { proto: 'TCP', srcPort, dstPort, tcpFlags: flags }, summary: 'MQTT', tag: 'TCP', appTag: 'MQTT', meta: { tcp: { flags: flagsByte } } }
    if (srcPort === 5672 || dstPort === 5672) return { l4: { proto: 'TCP', srcPort, dstPort, tcpFlags: flags }, summary: 'AMQP', tag: 'TCP', appTag: 'AMQP', meta: { tcp: { flags: flagsByte } } }
    if (srcPort === 88 || dstPort === 88) return { l4: { proto: 'TCP', srcPort, dstPort, tcpFlags: flags }, summary: 'Kerberos', tag: 'TCP', appTag: 'KERBEROS', meta: { tcp: { flags: flagsByte } } }
    if (srcPort === 11211 || dstPort === 11211) return { l4: { proto: 'TCP', srcPort, dstPort, tcpFlags: flags }, summary: 'Memcached', tag: 'TCP', appTag: 'MEMCACHED', meta: { tcp: { flags: flagsByte } } }

    // Default TCP
    const info = `${srcPort} → ${dstPort} [${flags}]`
    const tag = 'TCP'
    return { l4: { proto: 'TCP', srcPort, dstPort, tcpFlags: flags }, summary: info, tag, meta: { tcp: { flags: flagsByte } } }
  }
  if (proto === 17 && u.length >= off + 8) { // UDP
    const srcPort = (u[off] << 8) | u[off + 1]
    const dstPort = (u[off + 2] << 8) | u[off + 3]
    const dns = srcPort === 53 || dstPort === 53 ? decodeDns(u, off + 8) : undefined
    if (srcPort === 161 || dstPort === 161 || srcPort === 162 || dstPort === 162) return { l4: { proto: 'UDP', srcPort, dstPort }, summary: 'SNMP', tag: 'SNMP', appTag: 'SNMP' }
    if (srcPort === 514 || dstPort === 514) return { l4: { proto: 'UDP', srcPort, dstPort }, summary: 'Syslog', tag: 'SYSLOG', appTag: 'SYSLOG' }
    if (srcPort === 69 || dstPort === 69) return { l4: { proto: 'UDP', srcPort, dstPort }, summary: 'TFTP', tag: 'TFTP', appTag: 'TFTP' }
    if (srcPort === 137 || dstPort === 137 || srcPort === 138 || dstPort === 138) return { l4: { proto: 'UDP', srcPort, dstPort }, summary: 'NetBIOS', tag: 'NETBIOS', appTag: 'NETBIOS' }
    if (srcPort === 546 || dstPort === 546 || srcPort === 547 || dstPort === 547) return { l4: { proto: 'UDP', srcPort, dstPort }, summary: 'DHCPv6', tag: 'DHCPv6', appTag: 'DHCPv6' }
    if (srcPort === 520 || dstPort === 520) return { l4: { proto: 'UDP', srcPort, dstPort }, summary: 'RIP', tag: 'RIP', appTag: 'RIP' }
    if (srcPort === 5060 || dstPort === 5060) return { l4: { proto: 'UDP', srcPort, dstPort }, summary: 'SIP', tag: 'SIP', appTag: 'SIP' }
    if (srcPort === 1900 || dstPort === 1900) return { l4: { proto: 'UDP', srcPort, dstPort }, summary: 'SSDP', tag: 'UDP', appTag: 'SSDP' }
    if (srcPort === 3478 || dstPort === 3478 || sniffStun(u.subarray(off+8))) return { l4: { proto: 'UDP', srcPort, dstPort }, summary: 'STUN', tag: 'UDP', appTag: 'STUN/TURN' }
    if (srcPort === 5353 || dstPort === 5353) return { l4: { proto: 'UDP', srcPort, dstPort }, summary: 'mDNS', tag: 'UDP', appTag: 'MDNS' }
    if (srcPort === 5355 || dstPort === 5355) return { l4: { proto: 'UDP', srcPort, dstPort }, summary: 'LLMNR', tag: 'UDP', appTag: 'LLMNR' }
    if (srcPort === 5683 || dstPort === 5683) return { l4: { proto: 'UDP', srcPort, dstPort }, summary: 'CoAP', tag: 'UDP', appTag: 'COAP' }
    if (srcPort === 123 || dstPort === 123) return { l4: { proto: 'UDP', srcPort, dstPort }, summary: 'NTP', tag: 'UDP', appTag: 'NTP' }
    // RTP/RTCP heuristics
    const first = u[off]
    const second = u[off + 1]
    const v2 = (first & 0xc0) === 0x80
    if (v2) {
      if (second >= 200 && second <= 204) return { l4: { proto: 'UDP', srcPort, dstPort }, summary: 'RTCP', tag: 'RTCP', appTag: 'RTCP' }
      if (u.length >= off + 12) return { l4: { proto: 'UDP', srcPort, dstPort }, summary: 'RTP', tag: 'RTP', appTag: 'RTP' }
    }
    if (srcPort === 443 || dstPort === 443) return { l4: { proto: 'UDP', srcPort, dstPort }, summary: 'QUIC', tag: 'QUIC', appTag: 'QUIC' }
    const info = dns ? `DNS ${dns.summary}` : `${srcPort} → ${dstPort}`
    const tag = dns ? 'DNS' : 'UDP'
    return { l4: { proto: 'UDP', srcPort, dstPort }, summary: info, tag, appTag: dns ? 'DNS' : undefined, meta: dns ? { dns: { id: dns.id!, qr: dns.qr, name: dns.name, qtype: dns.qtype, qtypeName: dns.qtypeName } } : undefined }
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

function sniffHttpStartLine(payload: Uint8Array): { type: 'request'|'response'; method?: string; path?: string; status?: number; text?: string } | null {
  if (!payload || payload.length < 5) return null
  // Convert up to first 256 bytes to ASCII
  const max = Math.min(256, payload.length)
  let s = ''
  try { s = new TextDecoder('latin1').decode(payload.subarray(0, max)) } catch { return null }
  const line = (s.split(/\r?\n/, 1)[0] || '').trim()
  if (!line) return null
  const methods = ['GET','POST','PUT','DELETE','HEAD','OPTIONS','TRACE','PATCH']
  for (const m of methods) {
    if (line.startsWith(m + ' ')) {
      const parts = line.split(' ')
      const method = parts[0]
      const path = parts[1] || '/'
      if ((parts[2] || '').startsWith('HTTP/1.')) return { type: 'request', method, path }
    }
  }
  if (line.startsWith('HTTP/1.')) {
    const parts = line.split(' ')
    const status = parseInt(parts[1], 10)
    const text = parts.slice(2).join(' ')
    if (!isNaN(status)) return { type: 'response', status, text }
  }
  // HTTP/2 cleartext preface
  const h2pref = 'PRI * HTTP/2.0'
  if (line.startsWith(h2pref)) return { type: 'response', status: 0, text: 'HTTP/2 (preface)' }
  return null
}

function sniffTlsClientHello(payload: Uint8Array): { sni?: string } | null {
  // TLS record header: 5 bytes: ContentType(22), Version(0x03,0x01..0x04), Length(2)
  if (!payload || payload.length < 5) return null
  const ct = payload[0]
  const verMajor = payload[1]
  // const verMinor = payload[2]
  const len = (payload[3] << 8) | payload[4]
  if (ct !== 0x16 || verMajor !== 0x03 || payload.length < 5 + len) return null
  // Handshake: type(1)=ClientHello(1), length(3)
  if (payload.length < 5 + 4) return null
  const hsType = payload[5]
  if (hsType !== 0x01) return null
  // Very minimal ClientHello parser to SNI
  let p = 5 + 4 // after handshake header
  if (payload.length < p + 2) return { sni: undefined }
  // skip client_version(2) + random(32) + session_id
  p += 2 + 32
  if (payload.length < p + 1) return { sni: undefined }
  const sidLen = payload[p]; p += 1 + sidLen
  if (payload.length < p + 2) return { sni: undefined }
  const csLen = (payload[p] << 8) | payload[p+1]; p += 2 + csLen
  if (payload.length < p + 1) return { sni: undefined }
  const compLen = payload[p]; p += 1 + compLen
  if (payload.length < p + 2) return { sni: undefined }
  const extLen = (payload[p] << 8) | payload[p+1]; p += 2
  const end = Math.min(payload.length, p + extLen)
  while (p + 4 <= end) {
    const et = (payload[p] << 8) | payload[p+1]
    const el = (payload[p+2] << 8) | payload[p+3]
    p += 4
    if (p + el > end) break
    if (et === 0x0000 && el >= 5) { // server_name
      let q = p + 2 // list length(2)
      const listEnd = Math.min(p + el, end)
      while (q + 3 <= listEnd) {
        const nameType = payload[q]; q += 1
        const nl = (payload[q] << 8) | payload[q+1]; q += 2
        if (nameType === 0 && q + nl <= listEnd) {
          try {
            const sni = new TextDecoder('utf-8').decode(payload.subarray(q, q + nl))
            return { sni }
          } catch { return { sni: undefined } }
        }
        q += nl
      }
    }
    p += el
  }
  return { sni: undefined }
}

function ipv4ProtoToName(p: number): string {
  const m: Record<number,string> = {1:'ICMP',2:'IGMP',6:'TCP',17:'UDP',33:'DCCP',47:'GRE',50:'ESP',51:'AH',88:'EIGRP',89:'OSPF',132:'SCTP'}
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

function sniffStun(payload: Uint8Array): boolean {
  if (!payload || payload.length < 20) return false
  // STUN message: first 2 bits of type are 0, magic cookie 0x2112A442 at bytes 4..7
  const magic = (payload[4] << 24) | (payload[5] << 16) | (payload[6] << 8) | payload[7]
  return magic === 0x2112A442
}
