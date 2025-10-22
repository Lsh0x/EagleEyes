import type { ParsedCapture } from './parsers'
import type { PacketRow } from '../App'
import { extractL4Payload } from './decoders'

export type Exchange = {
  id: string
  protocol: 'arp'|'dns'|'http1'|'tcp-unknown'
  flowId?: string
  flow?: { a: string; b: string }
  request?: {
    startTime?: number|null
    endTime?: number|null
    summary?: any
    packetIds: number[]
  }
  response?: {
    startTime?: number|null
    endTime?: number|null
    summary?: any
    packetIds: number[]
  }
  timing?: { rttMs?: number|null }
  status: 'complete'|'partial'|'low-confidence'
}

export function buildExchanges(rows: PacketRow[], parsed: ParsedCapture | null): Exchange[] {
  const out: Exchange[] = []
  if (!rows.length) return out
  // ARP pairs (who-has/reply)
  out.push(...matchArp(rows))
  // DNS pairs
  out.push(...matchDns(rows))
  // HTTP/1 over TCP (best effort in-packet first-line detection)
  out.push(...matchHttp1(rows, parsed))
  // Generic TCP fallback (burst pairing) if nothing else
  out.push(...matchTcpBursts(rows, parsed))
  // Sort by request start time
  out.sort((a,b) => (a.request?.startTime || 0) - (b.request?.startTime || 0))
  return out
}

export type ExchangeGroup = { flowId: string; flow?: { a: string; b: string }; exchanges: Exchange[]; count: number; first?: number|null; last?: number|null }
export function groupExchangesByFlow(exchanges: Exchange[]): ExchangeGroup[] {
  const m = new Map<string, ExchangeGroup>()
  for (const ex of exchanges) {
    const key = ex.flowId || ex.flow ? `${ex.flow?.a}|${ex.flow?.b}` : ex.id
    const g = m.get(key) || { flowId: key, flow: ex.flow, exchanges: [], count: 0, first: null, last: null }
    g.exchanges.push(ex)
    g.count++
    const t = ex.request?.startTime || null
    if (t!=null) g.first = g.first==null ? t : Math.min(g.first, t)
    const tend = (ex.response?.endTime ?? ex.request?.endTime) || null
    if (tend!=null) g.last = g.last==null ? tend : Math.max(g.last, tend)
    m.set(key, g)
  }
  const out = Array.from(m.values())
  out.sort((a,b) => (a.first||0) - (b.first||0))
  return out
}

export function matchArp(rows: PacketRow[]): Exchange[] {
  const mapReq = new Map<string, PacketRow[]>()
  const out: Exchange[] = []
  for (const p of rows) {
    if ((p.proto||'').toUpperCase() !== 'ARP') continue
    if (!p.txnKey) continue // expects 'ARP|spa|tpa'
    const role = p.txnRole
    if (role === 'request') {
      const arr = mapReq.get(p.txnKey) || []
      arr.push(p)
      mapReq.set(p.txnKey, arr)
    } else if (role === 'reply') {
      const arr = mapReq.get(p.txnKey)
      if (arr && arr.length) {
        const req = arr.shift()!
        const id = `arp:${p.txnKey}`
        out.push({
          id,
          protocol: 'arp',
          flowId: p.txnKey,
          flow: keyToFlow(p.txnKey),
          request: { startTime: req.ts, endTime: req.ts, summary: parseArpKey(p.txnKey), packetIds: [req.index] },
          response: { startTime: p.ts, endTime: p.ts, summary: parseArpKey(p.txnKey), packetIds: [p.index] },
          timing: rtt(req.ts, p.ts),
          status: 'complete',
        })
      } else {
        out.push({ id: `arp:${p.txnKey}`, protocol: 'arp', flowId: p.txnKey, flow: keyToFlow(p.txnKey), response: { startTime: p.ts, endTime: p.ts, summary: parseArpKey(p.txnKey), packetIds: [p.index] }, status: 'partial' })
      }
    }
  }
  // leftovers => partial
  for (const [k, arr] of mapReq.entries()) {
    for (const req of arr) {
      out.push({ id: `arp:${k}`, protocol: 'arp', flowId: k, flow: keyToFlow(k), request: { startTime: req.ts, endTime: req.ts, summary: parseArpKey(k), packetIds: [req.index] }, status: 'partial' })
    }
  }
  return out
}

export function matchDns(rows: PacketRow[]): Exchange[] {
  const mapReq = new Map<string, PacketRow[]>()
  const out: Exchange[] = []
  for (const p of rows) {
    if ((p.proto||'').toUpperCase() !== 'DNS') continue
    if (!p.txnKey) continue
    const role = p.txnRole
    if (role === 'query') {
      const arr = mapReq.get(p.txnKey) || []
      arr.push(p)
      mapReq.set(p.txnKey, arr)
    } else if (role === 'response') {
      const arr = mapReq.get(p.txnKey)
      if (arr && arr.length) {
        const req = arr.shift()!
        const id = `dns:${p.txnKey}`
        out.push({
          id,
          protocol: 'dns',
          flowId: p.flowKey,
          flow: keyToFlow(p.flowKey),
          request: { startTime: req.ts, endTime: req.ts, summary: { id: req.dnsId }, packetIds: [req.index] },
          response: { startTime: p.ts, endTime: p.ts, summary: { id: p.dnsId }, packetIds: [p.index] },
          timing: rtt(req.ts, p.ts),
          status: 'complete',
        })
      } else {
        // unmatched response
        out.push({ id: `dns:${p.txnKey}`, protocol: 'dns', flowId: p.flowKey, flow: keyToFlow(p.flowKey), response: { startTime: p.ts, endTime: p.ts, summary: { id: p.dnsId }, packetIds: [p.index] }, status: 'partial' })
      }
    }
  }
  // leftovers => partial
  for (const [k, arr] of mapReq.entries()) {
    for (const req of arr) {
      out.push({ id: `dns:${k}`, protocol: 'dns', flowId: req.flowKey, flow: keyToFlow(req.flowKey), request: { startTime: req.ts, endTime: req.ts, summary: { id: req.dnsId }, packetIds: [req.index] }, status: 'partial' })
    }
  }
  return out
}

export function matchHttp1(rows: PacketRow[], parsed: ParsedCapture | null): Exchange[] {
  if (!parsed) return []
  // Group by TCP flow
  const byFlow = new Map<string, PacketRow[]>()
  for (const p of rows) {
    if ((p.proto||'').toUpperCase() !== 'TCP') continue
    if (!p.flowKey) continue
    // Consider only likely HTTP ports; but also sniff payload
    const arr = byFlow.get(p.flowKey) || []
    arr.push(p)
    byFlow.set(p.flowKey, arr)
  }
  const out: Exchange[] = []
  for (const [flowKey, arr] of byFlow.entries()) {
    // sort by time/index
    arr.sort((a,b)=> (a.ts||0)-(b.ts||0) || a.index-b.index)
    const reqs: { p: PacketRow; firstLine: string; method: string; path: string }[] = []
    const ress: { p: PacketRow; firstLine: string; status: number }[] = []
    for (const p of arr) {
      const pkt = parsed.packets[p.index-1]
      const ext = extractL4Payload(pkt.data)
      if (!ext || ext.proto !== 'TCP' || ext.length <= 0) continue
      const s = sniffHttpStart(pkt.data.subarray(ext.offset, ext.offset + Math.min(ext.length, 512)))
      if (!s) continue
      if (s.type === 'request') reqs.push({ p, firstLine: s.line, method: s.method!, path: s.path! })
      else if (s.type === 'response') ress.push({ p, firstLine: s.line, status: s.status! })
    }
    if (reqs.length === 0 && ress.length === 0) continue
    const n = Math.max(reqs.length, ress.length)
    for (let i=0;i<n;i++) {
      const rq = reqs[i]
      const rs = ress[i]
      const id = `http:${flowKey}#${i+1}`
      out.push({
        id,
        protocol: 'http1',
        flowId: flowKey,
        flow: keyToFlow(flowKey),
        request: rq ? { startTime: rq.p.ts, endTime: rq.p.ts, summary: { method: rq.method, path: rq.path, line: rq.firstLine }, packetIds: [rq.p.index] } : { packetIds: [] },
        response: rs ? { startTime: rs.p.ts, endTime: rs.p.ts, summary: { status: rs.status, line: rs.firstLine }, packetIds: [rs.p.index] } : { packetIds: [] },
        timing: rq && rs ? rtt(rq.p.ts, rs.p.ts) : undefined,
        status: rq && rs ? 'complete' : 'partial',
      })
    }
  }
  return out
}

export function matchTcpBursts(rows: PacketRow[], parsed: ParsedCapture | null): Exchange[] {
  if (!parsed) return []
  const out: Exchange[] = []
  const byFlow = new Map<string, PacketRow[]>()
  for (const p of rows) {
    if ((p.proto||'').toUpperCase() !== 'TCP') continue
    if (!p.flowKey) continue
    const arr = byFlow.get(p.flowKey) || []
    arr.push(p)
    byFlow.set(p.flowKey, arr)
  }
  for (const [flowKey, arr] of byFlow.entries()) {
    arr.sort((a,b)=> (a.ts||0)-(b.ts||0) || a.index-b.index)
    const bursts: { dir: 'A'|'B'; start: PacketRow; end: PacketRow; bytes: number; pktIds: number[] }[] = []
    const [aEnd] = endpoints(flowKey)
    let cur: typeof bursts[number] | null = null
    for (const p of arr) {
      const pkt = parsed.packets[p.index-1]
      const ext = extractL4Payload(pkt.data)
      if (!ext || ext.proto !== 'TCP' || ext.length <= 0) continue
      const dir = `${p.src}:${p.srcPort}` === aEnd ? 'A' : 'B'
      const size = Math.min(ext.length, 16384)
      if (!cur || cur.dir !== dir) {
        cur = { dir, start: p, end: p, bytes: size, pktIds: [p.index] }
        bursts.push(cur)
      } else {
        cur.end = p
        cur.bytes += size
        cur.pktIds.push(p.index)
      }
    }
    // pair consecutive bursts A then B
    for (let i=0;i+1<bursts.length;i+=2) {
      const rq = bursts[i]
      const rs = bursts[i+1]
      const id = `tcp:${flowKey}#${(i/2)+1}`
      out.push({
        id,
        protocol: 'tcp-unknown',
        flowId: flowKey,
        flow: keyToFlow(flowKey),
        request: { startTime: rq.start.ts, endTime: rq.end.ts, summary: { bytes: rq.bytes }, packetIds: rq.pktIds },
        response: { startTime: rs.start.ts, endTime: rs.end.ts, summary: { bytes: rs.bytes }, packetIds: rs.pktIds },
        timing: rtt(rq.start.ts, rs.start.ts),
        status: 'low-confidence',
      })
    }
  }
  return out
}

function sniffHttpStart(payload: Uint8Array): { type: 'request'|'response'; line: string; method?: string; path?: string; status?: number } | null {
  // attempt to read first line
  const txt = safeAscii(payload)
  const line = (txt.split(/\r?\n/, 1)[0] || '').trim()
  if (!line) return null
  const methods = ['GET','POST','PUT','DELETE','HEAD','OPTIONS','TRACE','PATCH']
  for (const m of methods) {
    if (line.startsWith(m + ' ')) {
      const parts = line.split(' ')
      const method = parts[0]
      const path = parts[1] || '/'
      if (parts[2] && parts[2].startsWith('HTTP/')) {
        return { type: 'request', line, method, path }
      }
    }
  }
  if (line.startsWith('HTTP/1.')) {
    const parts = line.split(' ')
    const status = parseInt(parts[1], 10)
    if (!isNaN(status)) return { type: 'response', line, status }
  }
  return null
}

function safeAscii(u: Uint8Array): string {
  try { return new TextDecoder('latin1', { fatal: false }).decode(u) } catch { return '' }
}

function rtt(a?: number|null, b?: number|null): { rttMs: number|null } {
  if (!a || !b) return { rttMs: null }
  return { rttMs: Math.max(0, (b - a) * 1000) }
}

function keyToFlow(flowKey?: string): { a: string; b: string } | undefined {
  if (!flowKey) return undefined
  const parts = flowKey.split('|')
  return { a: parts[1] || '', b: parts[2] || '' }
}

function parseArpKey(k: string): { spa?: string; tpa?: string } {
  const parts = k.split('|')
  return { spa: parts[1], tpa: parts[2] }
}

function endpoints(flowKey: string): [string, string] {
  const f = keyToFlow(flowKey)!
  return [f.a, f.b]
}