import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import './App.css'

import { parseCapture } from './lib/parsers'
import { decodePacket, extractL4Payload } from './lib/decoders'
import LeftPanel from './components/LeftPanel'
import type { Exchange } from './lib/matchers'
import { buildExchanges, groupExchangesByFlow } from './lib/matchers'

// Search suggestions (select to populate the input, then edit)
const FILTER_EXAMPLES: { label: string; query: string }[] = [
  { label: 'TCP SYN to 10.10.10.20:49156 from 10.10.10.10, len>100', query: 'proto:tcp src:10.10.10.10 dst:10.10.10.20 port:49156 len:>100 tcp.syn' },
  { label: 'TCP 443 between 192.168.88.1 ⇄ 192.168.88.2, len>=300', query: 'proto:tcp src:192.168.88.1 dst:192.168.88.2 port:443 len:>=300' },
  { label: 'UDP DNS to 8.8.8.8:53, small payloads', query: 'proto:udp ip:8.8.8.8 port:53 len:<200' },
  { label: 'DNS flow on 10.10.10.20 with id=53321, len<180', query: 'proto:dns ip:10.10.10.20 dns.id:53321 len:<180' },
  { label: 'ARP who-has (requests) around 192.168.1.1', query: 'proto:arp arp.op:request ip:192.168.1.1' },
  { label: 'HTTP-ish traffic (80/8080) to 10.10.10.20, len>300', query: 'proto:tcp port:80 port:8080 ip:10.10.10.20 len:>300' },
  { label: 'TCP teardown (FIN/RST) with 192.168.89.2, len>=60', query: 'proto:tcp ip:192.168.89.2 tcp.fin tcp.rst len:>=60' },
  { label: 'NTP-like: UDP 123 from 10.10.10.20 → 10.10.10.10, len<180', query: 'proto:udp src:10.10.10.20 dst:10.10.10.10 port:123 len:<180' },
  { label: 'SSH attempts: TCP 22 from 10.10.10.10 → 10.10.10.20, len<200', query: 'proto:tcp src:10.10.10.10 dst:10.10.10.20 port:22 len:<200' },
  { label: 'ACK-heavy TCP with 192.168.88.1 on :49156, len>60', query: 'proto:tcp ip:192.168.88.1 port:49156 tcp.ack len:>60' },
  { label: 'DNS on 192.168.89.2 with txn id=1, len<120', query: 'proto:dns ip:192.168.89.2 dns.id:1 len:<120' },
  { label: 'Any traffic with peer 8.8.8.8, mixed', query: 'ip:8.8.8.8 proto:tcp proto:udp len:>60' },
]

// Safety limits to avoid browser crashes with very large captures
const HARD_LIMIT_BYTES = 250 * 1024 * 1024; // 250 MB: above this, refuse to load
const SOFT_LIMIT_BYTES = 50 * 1024 * 1024;  // 50 MB: above this, load only the first chunk
const MAX_PACKET_ROWS = 100_000;            // cap number of rows held in memory

export type PacketRow = {
  index: number
  ts: number | null // epoch seconds (float)
  capturedLen: number
  originalLen: number
  ifIndex?: number
  src?: string
  dst?: string
  srcPort?: number
  dstPort?: number
  proto?: string
  app?: string
  info?: string
  flowKey?: string
  txnKey?: string
  txnRole?: string
  tcpFlags?: number
  dnsId?: number
  arpOp?: number
}

function bytesToHuman(n: number) {
  if (n < 1024) return `${n} B`
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`
  return `${(n / (1024 * 1024)).toFixed(1)} MB`
}

function App() {
  const [fileName, setFileName] = useState<string | null>(null)
  const parsedRef = useRef<import('./lib/parsers').ParsedCapture | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [notice, setNotice] = useState<string | null>(null)
  const [packets, setPackets] = useState<PacketRow[]>([])
  const [filter, setFilter] = useState('')
  const [selectedProtos, setSelectedProtos] = useState<Set<string>>(new Set())
  const [selectedIndex, setSelectedIndex] = useState<number | null>(null)
  const [flowKey, setFlowKey] = useState<string | null>(null)
  const [ipFocus, setIpFocus] = useState<string | null>(null)
  const [ipFocusRole, setIpFocusRole] = useState<'src' | 'dst' | 'both'>('both')
  const [sortBy, setSortBy] = useState<'time' | 'peer' | 'proto'>('time')
  const [peerFocus, setPeerFocus] = useState<string | null>(null)
  const [viewMode, setViewMode] = useState<'list' | 'grouped'>('list')
  const [expandedPeers, setExpandedPeers] = useState<Set<string>>(new Set())
  const [txnGrouped, setTxnGrouped] = useState<boolean>(false)
  const [txnFocus, setTxnFocus] = useState<string | null>(null)
  const [expandedTxns, setExpandedTxns] = useState<Set<string>>(new Set())
  const [panelTab, setPanelTab] = useState<'packet'|'stats'>('packet')
  const [showExchanges, setShowExchanges] = useState<boolean>(false)
  const [collapsePairs, setCollapsePairs] = useState<boolean>(false)
  const [sidePinned, setSidePinned] = useState<boolean>(false)
  const [sideWidth, setSideWidth] = useState<number>(() => {
    const s = Number(localStorage.getItem('eagleview.sideWidth') || '320')
    return isFinite(s) && s >= 260 && s <= 560 ? s : 320
  })
  useEffect(() => { localStorage.setItem('eagleview.sideWidth', String(sideWidth)) }, [sideWidth])
  const exchanges = useMemo<Exchange[]>(() => buildExchanges(packets, parsedRef.current), [packets])
  const exByPacket = useMemo<Map<number, Exchange>>(() => {
    const m = new Map<number, Exchange>()
    for (const ex of exchanges) {
      for (const id of ex.request?.packetIds || []) m.set(id, ex)
      for (const id of ex.response?.packetIds || []) m.set(id, ex)
    }
    return m
  }, [exchanges])
  const rowByIndex = useMemo<Map<number, PacketRow>>(()=> {
    const m = new Map<number, PacketRow>()
    for (const r of packets) m.set(r.index, r)
    return m
  }, [packets])
  const [exGrouped, setExGrouped] = useState<boolean>(true)
  const exGroups = useMemo(()=> exGrouped ? groupExchangesByFlow(exchanges) : [], [exchanges, exGrouped])

  const availableProtos = useMemo(() => {
    const set = new Set<string>()
    for (const p of packets) {
      const pr = (p.proto || '').toUpperCase()
      if (pr) set.add(pr)
    }
    return Array.from(set).sort()
  }, [packets])

  const toggleProto = (proto: string) => {
    setSelectedProtos((prev) => {
      const next = new Set(prev)
      const key = proto.toUpperCase()
      if (next.has(key)) next.delete(key)
      else next.add(key)
      return next
    })
  }

  const clearProtos = () => setSelectedProtos(new Set())

  const resetAll = () => {
    setFilter('')
    setSelectedProtos(new Set())
    setSelectedIndex(null)
    setFlowKey(null)
    setIpFocus(null)
    setPeerFocus(null)
    setViewMode('list')
    setTxnGrouped(false)
    setTxnFocus(null)
    setExpandedPeers(new Set())
    setExpandedTxns(new Set())
    setShowExchanges(false)
    setCollapsePairs(false)
    setSortBy('time')
  }

  const onFiles = useCallback(async (files: FileList | null) => {
    setError(null)
    setNotice(null)
    setPackets([])
    if (!files || files.length === 0) return
    const f = files[0]
    setFileName(f.name)
    try {
      // Enforce hard size limit
      if (f.size > HARD_LIMIT_BYTES) {
        setError(`File is too large for in-browser parsing (${bytesToHuman(f.size)} > ${bytesToHuman(HARD_LIMIT_BYTES)}). Please trim or filter the capture (e.g., by time, hosts, or ports) and try again.`)
        return
      }
      // Load fully or only the first chunk depending on size
      const readEnd = f.size > SOFT_LIMIT_BYTES ? SOFT_LIMIT_BYTES : f.size
      const buf = await f.slice(0, readEnd).arrayBuffer()
      const parsed = parseCapture(buf)
      parsedRef.current = parsed

      // Prepare notice messages
      const notices: string[] = []
      if (readEnd < f.size) {
        notices.push(`Loaded only the first ${bytesToHuman(readEnd)} of ${bytesToHuman(f.size)} (large file).`)
      }

      const rows = parsed.packets.length > MAX_PACKET_ROWS ? parsed.packets.slice(0, MAX_PACKET_ROWS) : parsed.packets
      if (parsed.packets.length > MAX_PACKET_ROWS) {
        notices.push(`Showing the first ${MAX_PACKET_ROWS.toLocaleString()} packets out of ${parsed.packets.length.toLocaleString()}.`)
      }

      if (notices.length) setNotice(notices.join(' '))

      setPackets(
        rows.map((p, i) => {
          const dec = decodePacket(p)
          const src = dec.l3?.src ?? dec.l2?.srcMac
          const dst = dec.l3?.dst ?? dec.l2?.dstMac
          const proto = dec.protocolTag
          const srcPort = dec.l4?.srcPort
          const dstPort = dec.l4?.dstPort
          const flowKey = buildFlowKey(proto, src, dst, srcPort, dstPort)
          const { txnKey, txnRole } = buildTxn(proto, dec, src, dst, srcPort, dstPort, flowKey)
          return {
            index: i + 1,
            ts: p.ts,
            capturedLen: p.capturedLen,
            originalLen: p.originalLen,
            ifIndex: p.ifIndex,
            src,
            dst,
            srcPort,
            dstPort,
            proto,
            info: dec.summary,
            app: dec.appTag,
            flowKey,
            txnKey,
            txnRole,
            tcpFlags: dec?.meta?.tcp?.flags,
            dnsId: dec?.meta?.dns?.id,
            arpOp: dec?.meta?.arp?.op,
          }
        }),
      )
    } catch (e: any) {
      setError(e?.message || 'Failed to parse file')
    }
  }, [])

  const filtered = useMemo(() => {
    let arr = packets
    if (flowKey) {
      arr = arr.filter((p) => p.flowKey === flowKey)
    }
    if (txnFocus) {
      arr = arr.filter((p) => (exByPacket.get(p.index)?.id === txnFocus))
    }
    if (ipFocus) {
      if (ipFocusRole === 'src') arr = arr.filter((p) => p.src === ipFocus)
      else if (ipFocusRole === 'dst') arr = arr.filter((p) => p.dst === ipFocus)
      else arr = arr.filter((p) => p.src === ipFocus || p.dst === ipFocus)
      if (peerFocus) {
        if (ipFocusRole === 'src') arr = arr.filter((p) => p.dst === peerFocus)
        else if (ipFocusRole === 'dst') arr = arr.filter((p) => p.src === peerFocus)
        else arr = arr.filter((p) => (p.src === ipFocus && p.dst === peerFocus) || (p.dst === ipFocus && p.src === peerFocus))
      }
    }
    if (selectedProtos.size > 0) {
      arr = arr.filter((p) => selectedProtos.has((p.proto || '').toUpperCase()) || selectedProtos.has((p.app || '').toUpperCase()))
    }
    if (filter.trim()) {
      const tokens = filter.trim().split(/\s+/)
      arr = arr.filter((p) => tokens.every((t) => matchToken(p, t)))
    }
    // sorting for list view
    const withSortHelper = arr.map((p) => ({
      p,
      peer: ipFocus ? (p.src === ipFocus ? p.dst : p.src) : undefined,
    }))
    withSortHelper.sort((a, b) => {
      if (sortBy === 'peer') {
        const pa = (a.peer || '').toLowerCase()
        const pb = (b.peer || '').toLowerCase()
        if (pa !== pb) return pa < pb ? -1 : 1
        return (a.p.ts || 0) - (b.p.ts || 0)
      }
      if (sortBy === 'proto') {
        const pa = (a.p.proto || '').toLowerCase()
        const pb = (b.p.proto || '').toLowerCase()
        if (pa !== pb) return pa < pb ? -1 : 1
        return (a.p.ts || 0) - (b.p.ts || 0)
      }
      // time
      return (a.p.ts || 0) - (b.p.ts || 0)
    })
    return withSortHelper.map((x) => x.p)
  }, [packets, filter, selectedProtos, flowKey, ipFocus, sortBy, peerFocus, ipFocusRole])

  const groups = useMemo(() => {
    if (!ipFocus) return [] as { peer: string; count: number; bytes: number; first: number; last: number; protos: string[]; sample: PacketRow[] }[]
    let arr = packets
    if (flowKey) arr = arr.filter((p) => p.flowKey === flowKey)
    // ignore peerFocus here to show full overview
    if (ipFocusRole === 'src') arr = arr.filter((p) => p.src === ipFocus)
    else if (ipFocusRole === 'dst') arr = arr.filter((p) => p.dst === ipFocus)
    else arr = arr.filter((p) => p.src === ipFocus || p.dst === ipFocus)
    if (selectedProtos.size > 0) arr = arr.filter((p) => selectedProtos.has((p.proto || '').toUpperCase()))
    if (filter.trim()) {
      const tokens = filter.trim().split(/\s+/)
      arr = arr.filter((p) => tokens.every((t) => matchToken(p, t)))
    }
    const map = new Map<string, { peer: string; count: number; bytes: number; first: number; last: number; protos: Set<string>; sample: PacketRow[] }>()
    for (const p of arr) {
      const peer = ipFocusRole === 'src' ? p.dst : ipFocusRole === 'dst' ? p.src : (p.src === ipFocus ? p.dst : p.src)
      if (!peer) continue
      const g = map.get(peer) || { peer, count: 0, bytes: 0, first: Number.POSITIVE_INFINITY, last: 0, protos: new Set<string>(), sample: [] }
      g.count += 1
      g.bytes += p.capturedLen
      g.first = Math.min(g.first, p.ts || Number.POSITIVE_INFINITY)
      g.last = Math.max(g.last, p.ts || 0)
      if (p.proto) g.protos.add(p.proto)
      if (g.sample.length < 20) g.sample.push(p)
      map.set(peer, g)
    }
    let out = Array.from(map.values()).map((g) => ({ peer: g.peer, count: g.count, bytes: g.bytes, first: g.first, last: g.last, protos: Array.from(g.protos).sort(), sample: g.sample }))
    // sort
    if (sortBy === 'peer') out.sort((a, b) => a.peer.localeCompare(b.peer))
    else if (sortBy === 'proto') out.sort((a, b) => (a.protos[0] || '').localeCompare(b.protos[0] || ''))
    else out.sort((a, b) => (a.first || 0) - (b.first || 0))
    return out
  }, [ipFocus, ipFocusRole, packets, flowKey, selectedProtos, filter, sortBy])

  const txnGroups = useMemo(() => {
    if (!txnGrouped) return [] as { key: string; proto: string; label: string; req: number; resp: number; other: number; first: number; last: number }[]
    // Build from exchanges so it works for DNS/ARP/HTTP/TCP
    let exList = exchanges
    if (flowKey) exList = exList.filter(ex => ex.flowId === flowKey)
    if (ipFocus) {
      exList = exList.filter(ex => {
        const a = ex.flow?.a || ''
        const b = ex.flow?.b || ''
        if (ipFocusRole === 'src') return a.startsWith(ipFocus + ':')
        if (ipFocusRole === 'dst') return b.startsWith(ipFocus + ':')
        return a.startsWith(ipFocus + ':') || b.startsWith(ipFocus + ':')
      })
    }
    if (selectedProtos.size > 0) exList = exList.filter(ex => selectedProtos.has(ex.protocol.toUpperCase()))
    if (filter.trim()) {
      const tokens = filter.trim().split(/\s+/)
      exList = exList.filter(ex => tokens.every(t => {
        const v = t.toLowerCase()
        return (
          ex.id.toLowerCase().includes(v) ||
          ex.protocol.toLowerCase().includes(v) ||
          (ex.flow ? `${ex.flow.a} ${ex.flow.b}`.toLowerCase().includes(v) : false)
        )
      }))
    }
    const out = exList.map(ex => ({
      key: ex.id,
      proto: ex.protocol.toUpperCase(),
      label: ex.id,
      req: ex.request?.packetIds?.length || 0,
      resp: ex.response?.packetIds?.length || 0,
      other: 0,
      first: ex.request?.startTime || ex.response?.startTime || 0,
      last: ex.response?.endTime || ex.request?.endTime || 0,
    }))
    out.sort((a, b) => (a.first || 0) - (b.first || 0))
    return out
  }, [txnGrouped, exchanges, flowKey, ipFocus, ipFocusRole, selectedProtos, filter])

  // Stats for side panel (based on current filtered rows)
  const stats = useMemo(() => {
    const arr = packets
    const totalPackets = arr.length
    const totalBytes = arr.reduce((a, p) => a + (p.capturedLen || 0), 0)
    const times = arr.map(p => p.ts || 0).filter(Boolean)
    const first = times.length ? Math.min(...times) : null
    const last = times.length ? Math.max(...times) : null
    const duration = first != null && last != null ? Math.max(0, last - first) : null
    const pps = duration && duration > 0 ? totalPackets / duration : null
    const bps = duration && duration > 0 ? (totalBytes * 8) / duration : null
    const byProto = new Map<string, { count: number; bytes: number }>()
    const byPeer = new Map<string, { count: number; bytes: number }>()
    const tcpPorts = new Map<number, { count: number; bytes: number }>()
    const udpPorts = new Map<number, { count: number; bytes: number }>()
    let focusIn = 0, focusOut = 0, focusInBytes = 0, focusOutBytes = 0
    for (const p of arr) {
      const pr = (p.proto || 'OTHER').toUpperCase()
      const ep = byProto.get(pr) || { count: 0, bytes: 0 }
      ep.count += 1
      ep.bytes += p.capturedLen || 0
      byProto.set(pr, ep)
      for (const ip of [p.src, p.dst]) {
        if (!ip) continue
        const e = byPeer.get(ip) || { count: 0, bytes: 0 }
        e.count += 1
        e.bytes += p.capturedLen || 0
        byPeer.set(ip, e)
      }
      if (p.proto?.toUpperCase() === 'TCP' && (p.srcPort != null || p.dstPort != null)) {
        const ports = [p.srcPort, p.dstPort].filter((x)=>x!=null) as number[]
        for (const port of ports) {
          const e = tcpPorts.get(port) || { count: 0, bytes: 0 }
          e.count += 1
          e.bytes += p.capturedLen || 0
          tcpPorts.set(port, e)
        }
      } else if (p.proto?.toUpperCase() === 'UDP' && (p.srcPort != null || p.dstPort != null)) {
        const ports = [p.srcPort, p.dstPort].filter((x)=>x!=null) as number[]
        for (const port of ports) {
          const e = udpPorts.get(port) || { count: 0, bytes: 0 }
          e.count += 1
          e.bytes += p.capturedLen || 0
          udpPorts.set(port, e)
        }
      }
      if (ipFocus) {
        if (p.dst === ipFocus) { focusIn += 1; focusInBytes += (p.capturedLen || 0) }
        if (p.src === ipFocus) { focusOut += 1; focusOutBytes += (p.capturedLen || 0) }
      }
    }
    const protoList = Array.from(byProto.entries()).map(([proto, v]) => ({ proto, ...v })).sort((a, b) => b.bytes - a.bytes)
    const topPeers = Array.from(byPeer.entries()).map(([peer, v]) => ({ peer, ...v })).sort((a, b) => b.bytes - a.bytes).slice(0, 10)
    const topTCP = Array.from(tcpPorts.entries()).map(([port, v]) => ({ port, ...v })).sort((a,b)=>b.bytes-a.bytes).slice(0,10)
    const topUDP = Array.from(udpPorts.entries()).map(([port, v]) => ({ port, ...v })).sort((a,b)=>b.bytes-a.bytes).slice(0,10)
    const uniquePeers = byPeer.size
    const focus = ipFocus ? { inCount: focusIn, outCount: focusOut, inBytes: focusInBytes, outBytes: focusOutBytes } : null
    return { totalPackets, totalBytes, first, last, duration, pps, bps, uniquePeers, protoList, topPeers, topTCP, topUDP, focus }
  }, [packets])

  const [streamKey, setStreamKey] = useState<string | null>(null)
  const streamPackets = useMemo(() => {
    if (!streamKey || !parsedRef.current) return [] as { dir: 'A→B' | 'B→A'; time: number; data: Uint8Array }[]
    // Derive endpoints from key like PROTO|a:port|b:port
    const parts = streamKey.split('|')
    const a = parts[1] || ''
    const out: { dir: 'A→B' | 'B→A'; time: number; data: Uint8Array }[] = []
    for (const row of packets) {
      if (row.flowKey !== streamKey || row.index < 1) continue
      const pkt = parsedRef.current.packets[row.index - 1]
      const ext = extractL4Payload(pkt.data)
      if (!ext || ext.length === 0) continue
      const sp = `${row.src}:${row.srcPort}`
      const dir: 'A→B' | 'B→A' = sp === a ? 'A→B' : 'B→A'
      out.push({ dir, time: row.ts || 0, data: pkt.data.subarray(ext.offset, ext.offset + Math.min(ext.length, 16384)) })
    }
    out.sort((x, y) => x.time - y.time)
    return out
  }, [streamKey, packets])

  function hexPreview(u: Uint8Array, off: number, len: number): string {
    const end = Math.min(u.length, off + len)
    let s = ''
    for (let p = off; p < end; p += 16) {
      const slice = u.subarray(p, Math.min(end, p + 16))
      const hex = Array.from(slice).map(b => b.toString(16).padStart(2, '0')).join(' ')
      const asc = Array.from(slice).map(b => (b >= 32 && b < 127) ? String.fromCharCode(b) : '.').join('')
      s += hex.padEnd(16*3-1, ' ') + '  ' + asc + '\n'
    }
    return s
  }

  function textPreview(u: Uint8Array, off: number, len: number): string {
    const end = Math.min(u.length, off + len)
    const slice = u.subarray(off, end)
    // try UTF-8 first, fallback to latin1
    let s = ''
    try { s = new TextDecoder('utf-8',{fatal:false}).decode(slice) } catch { s = '' }
    if (!s) { try { s = new TextDecoder('latin1',{fatal:false}).decode(slice) } catch { s = '' } }
    // replace non-printables except common whitespace
    s = s.replace(/[^\x09\x0A\x0D\x20-\x7E]/g, '.')
    return s
  }

  const selectedPacket = useMemo(() => {
    if (!selectedIndex || !parsedRef.current) return null
    const p = parsedRef.current.packets[selectedIndex - 1]
    const dec = decodePacket(p)
    const payload = extractL4Payload(p.data)
    const hex = payload ? hexPreview(p.data, payload.offset, Math.min(64, payload.length)) : 'N/A'
    return { dec, hex }
  }, [selectedIndex, packets])

  function buildFlowKey(proto?: string, src?: string, dst?: string, sp?: number, dp?: number): string | undefined {
    const pr = (proto || '').toUpperCase()
    // Track only for TCP/UDP/DNS for flow
    if (!pr || !(pr === 'TCP' || pr === 'UDP' || pr === 'DNS')) return undefined
    if (!src || !dst || sp == null || dp == null) return undefined
    const a = `${src}:${sp}`
    const b = `${dst}:${dp}`
    const [e1, e2] = a.localeCompare(b) <= 0 ? [a, b] : [b, a]
    return `${pr}|${e1}|${e2}`
  }

  function buildTxn(proto?: string, dec?: any, src?: string, dst?: string, sp?: number, dp?: number, flowKey?: string): { txnKey?: string; txnRole?: string } {
    const pr = (proto || '').toUpperCase()
    if (pr === 'ARP' && dec?.meta?.arp) {
      const spa = dec.meta.arp.spa
      const tpa = dec.meta.arp.tpa
      if (spa && tpa) {
        const key = `ARP|${spa}|${tpa}`
        const role = dec.meta.arp.op === 1 ? 'request' : dec.meta.arp.op === 2 ? 'reply' : 'other'
        return { txnKey: key, txnRole: role }
      }
    }
    if (pr === 'DNS' && dec?.meta?.dns) {
      if (dec.meta.dns.id != null && src && dst && sp != null && dp != null) {
        const a = `${src}:${sp}`
        const b = `${dst}:${dp}`
        const [e1, e2] = a.localeCompare(b) <= 0 ? [a, b] : [b, a]
        const key = `DNS|${dec.meta.dns.id}|${e1}|${e2}`
        const role = dec.meta.dns.qr ? 'response' : 'query'
        return { txnKey: key, txnRole: role }
      }
    }
    if (pr === 'TCP' && dec?.meta?.tcp && flowKey) {
      const f = dec.meta.tcp.flags as number
      const syn = (f & 0x02) !== 0
      const ack = (f & 0x10) !== 0
      const rst = (f & 0x04) !== 0
      const fin = (f & 0x01) !== 0
      let role: string | undefined
      if (syn && !ack) role = 'syn'
      else if (syn && ack) role = 'syn-ack'
      else if (ack && !rst && !fin) role = 'ack'
      else if (fin) role = 'fin'
      else if (rst) role = 'rst'
      if (role) return { txnKey: `TCP-HS|${flowKey}`, txnRole: role }
    }
    return {}
  }

  function matchToken(p: PacketRow, t: string): boolean {
    const [k, vRaw] = t.includes(':') ? (t.split(':', 2) as [string, string]) : ['text', t]
    const v = vRaw.toLowerCase()
    switch (k.toLowerCase()) {
      case 'proto':
        return (p.proto || '').toLowerCase().includes(v)
      case 'ip':
      case 'host':
      case 'addr':
        return (
          (p.src || '').toLowerCase().includes(v) || (p.dst || '').toLowerCase().includes(v)
        )
      case 'src':
        return (p.src || '').toLowerCase().includes(v)
      case 'dst':
        return (p.dst || '').toLowerCase().includes(v)
      case 'port': {
        const vi = parseInt(v, 10)
        return isNaN(vi) ? false : (p.info || '').match(/\b(\d+)\s*→\s*(\d+)/)?.some(n => parseInt(n,10)===vi) || (p.info||'').includes(` ${vi} `)
      }
      case 'dns.id': {
        const n = parseInt(v, 10)
        return p.dnsId === n
      }
      case 'arp.op': {
        if (v === 'request') return p.arpOp === 1
        if (v === 'reply') return p.arpOp === 2
        const n = parseInt(v, 10)
        return p.arpOp === n
      }
      case 'tcp.syn': return !!(p.tcpFlags && (p.tcpFlags & 0x02))
      case 'tcp.ack': return !!(p.tcpFlags && (p.tcpFlags & 0x10))
      case 'tcp.fin': return !!(p.tcpFlags && (p.tcpFlags & 0x01))
      case 'tcp.rst': return !!(p.tcpFlags && (p.tcpFlags & 0x04))
      case 'len': {
        const m = v.match(/([<>]=?|=)?\s*(\d+)/)
        if (!m) return false
        const op = m[1] || '='
        const n = parseInt(m[2], 10)
        const L = p.capturedLen
        if (op === '>') return L > n
        if (op === '>=') return L >= n
        if (op === '<') return L < n
        if (op === '<=') return L <= n
        return L === n
      }
      default: {
        const q = v
        return (
          `${p.index}`.includes(q) ||
          (p.proto || '').toLowerCase().includes(q) ||
          (p.src || '').toLowerCase().includes(q) ||
          (p.dst || '').toLowerCase().includes(q) ||
          (p.info || '').toLowerCase().includes(q)
        )
      }
    }
  }

  // Keyboard navigation (ArrowUp/ArrowDown) over filtered list
  useEffect(() => {
    function isTypingInInput(target: any) {
      const tag = (target?.tagName || '').toLowerCase()
      return tag === 'input' || tag === 'textarea' || tag === 'select' || target?.isContentEditable
    }
    const onKey = (e: KeyboardEvent) => {
      if (isTypingInInput(e.target)) return
      if (e.key !== 'ArrowDown' && e.key !== 'ArrowUp') return
      if (!filtered.length) return
      e.preventDefault()
      const idx = selectedIndex
      let pos = filtered.findIndex((p) => p.index === idx)
      if (pos === -1) pos = 0
      if (e.key === 'ArrowDown') pos = Math.min(filtered.length - 1, pos + 1)
      else pos = Math.max(0, pos - 1)
      setSelectedIndex(filtered[pos].index)
      // ensure visible
      requestAnimationFrame(() => {
        const el = document.getElementById(`row-${filtered[pos].index}`)
        el?.scrollIntoView({ block: 'nearest' })
      })
    }
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [filtered, selectedIndex])

  // ESC to close selection/transaction focus
  useEffect(() => {
    const onEsc = (e: KeyboardEvent) => {
      if (e.key === 'Escape') {
        setSelectedIndex(null)
      }
    }
    window.addEventListener('keydown', onEsc)
    return () => window.removeEventListener('keydown', onEsc)
  }, [])

  function openPacketDetails(idx: number) {
    setSelectedIndex(idx)
    setSidePinned(true)
  }

  return (
    <div className="app-root">
      <header className="topbar">
        <div className="brand">EagleView</div>
        <div className="actions" style={{display:'flex', gap:8}}>
          <label className="btn" htmlFor="file-input">
            + Open PCAP/PCAPNG
          </label>
          <input
            id="file-input"
            type="file"
            accept=".pcap,.pcapng,application/octet-stream"
            onChange={(e) => onFiles(e.target.files)}
            style={{ display: 'none' }}
          />
        </div>
      </header>

      <main className={`content`} style={{ marginLeft: sidePinned ? sideWidth : 48 }}>
        <section
          className="dropzone"
          onDragOver={(e) => e.preventDefault()}
          onDrop={(e) => {
            e.preventDefault()
            onFiles(e.dataTransfer.files)
          }}
        >
          <p>
            {fileName ? (
              <>
                Loaded <strong>{fileName}</strong>
              </>
            ) : (
              <>Drag & drop a .pcap/.pcapng here or use the button above</>
            )}
          </p>
          {error && <p className="error">{error}</p>}
          {notice && <p className="notice">{notice}</p>}
        </section>

        <section className="toolbar">
          <div className="toolbar-top">
<input
              className="input"
              placeholder="Start typing or pick an example…"
              list="filter-examples"
              value={filter}
              onChange={(e) => setFilter(e.target.value)}
            />
            <datalist id="filter-examples">
              {FILTER_EXAMPLES.map((ex) => (
                <option key={ex.query} value={ex.query} label={ex.label} />
              ))}
            </datalist>
            <button className="chip clear" onClick={resetAll} title="Clear all filters and views">Reset</button>
            <div className="stats">
              <span>{filtered.length} packets</span>
              {packets.length > 0 && (
                <span>
                  • total captured {bytesToHuman(packets.reduce((a, b) => a + b.capturedLen, 0))}
                </span>
              )}
            </div>
          </div>
          <div className="proto-chips">
            {availableProtos.map((pr) => (
              <button
                key={pr}
                className={`chip ${selectedProtos.has(pr.toUpperCase()) ? 'active' : ''}`}
                onClick={() => toggleProto(pr)}
                title={`Filter proto:${pr.toLowerCase()}`}
              >
                {pr}
              </button>
            ))}
            {flowKey && (
              <button className="chip active" onClick={() => setFlowKey(null)} title="Clear flow tracking">
                Flow tracking ×
              </button>
            )}
            {ipFocus && (
              <>
                <button className="chip active" onClick={() => { setIpFocus(null); setPeerFocus(null) }} title="Clear IP focus">
                  IP: {ipFocus} ({ipFocusRole}) ×
                </button>
                <span className="hint">Role:</span>
                <button className={`chip ${ipFocusRole==='src'?'active':''}`} onClick={() => setIpFocusRole('src')} title="Only packets where this IP is Source">Src</button>
                <button className={`chip ${ipFocusRole==='dst'?'active':''}`} onClick={() => setIpFocusRole('dst')} title="Only packets where this IP is Destination">Dst</button>
                <button className={`chip ${ipFocusRole==='both'?'active':''}`} onClick={() => setIpFocusRole('both')} title="Packets where this IP is Source or Destination">Both</button>
                <span className="hint">View:</span>
                <button className={`chip ${viewMode==='grouped'?'active':''}`} onClick={() => setViewMode('grouped')} title="Group by other IP">Grouped</button>
                <button className={`chip ${viewMode==='list'?'active':''}`} onClick={() => setViewMode('list')} title="List packets">List</button>
                {peerFocus && (
                  <button className="chip active" onClick={() => setPeerFocus(null)} title="Clear peer">
                    Peer: {peerFocus} ×
                  </button>
                )}
              </>
            )}
            {availableProtos.length > 0 && selectedProtos.size > 0 && (
              <button className="chip clear" onClick={clearProtos} title="Clear protocol filters">Clear</button>
            )}
            <span className="hint">Group:</span>
            <button className={`chip ${txnGrouped?'active':''}`} onClick={() => setTxnGrouped(v=>!v)} title="Group protocol transactions">Transactions</button>
            <button className={`chip ${showExchanges?'active':''}`} onClick={() => setShowExchanges(v=>!v)} title="Show request–response pairs">Exchanges</button>
            <button className={`chip ${collapsePairs?'active':''}`} onClick={() => setCollapsePairs(v=>!v)} title="Collapse request–response pairs in list">Collapse pairs</button>
            {showExchanges && (
              <>
                <span className="hint">View:</span>
                <button className={`chip ${exGrouped?'active':''}`} onClick={()=> setExGrouped(true)}>By flow</button>
                <button className={`chip ${!exGrouped?'active':''}`} onClick={()=> setExGrouped(false)}>Flat</button>
              </>
            )}
            {txnFocus && (
              <button className="chip active" onClick={() => setTxnFocus(null)} title="Clear transaction focus">Txn ×</button>
            )}
          </div>
          {ipFocus && (
            <div className="sorter">
              <label>
                Sort by:
                <select className="select" value={sortBy} onChange={(e) => setSortBy(e.target.value as any)}>
                  <option value="time">Time</option>
                  <option value="peer">Other IP</option>
                  <option value="proto">Protocol</option>
                </select>
              </label>
            </div>
          )}
        </section>

        {showExchanges ? (
          exGrouped ? (
            <section className="table-wrap">
              <table className="table">
                <thead>
                  <tr>
                    <th>Flow</th>
                    <th>Count</th>
                    <th>First</th>
                    <th>Last</th>
                    <th>Actions</th>
                  </tr>
                </thead>
                <tbody>
                  {exGroups.slice(0,500).map(g => (
                    <tr key={g.flowId}>
                      <td className="mono">{g.flow ? `${g.flow.a} ⇄ ${g.flow.b}` : g.flowId}</td>
                      <td>{g.count}</td>
                      <td>{g.first ? new Date(g.first*1000).toISOString().split('T')[1].replace('Z','') : '-'}</td>
                      <td>{g.last ? new Date(g.last*1000).toISOString().split('T')[1].replace('Z','') : '-'}</td>
                      <td>
                        <button className="mini" onClick={()=> setFlowKey(`TCP|${g.flow?.a}|${g.flow?.b}`)} title="Follow flow">Follow</button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
              {exGroups.length === 0 && <div className="empty">No exchanges detected</div>}
            </section>
          ) : (
            <section className="table-wrap">
              <table className="table">
                <thead>
                  <tr>
                    <th>Protocol</th>
                    <th>Flow</th>
                    <th>Request</th>
                    <th>Response</th>
                    <th>Start</th>
                    <th>RTT</th>
                    <th>Actions</th>
                  </tr>
                </thead>
                <tbody>
                  {exchanges.slice(0,1000).map((ex) => (
                    <tr key={ex.id}>
                      <td><span className={'badge proto-' + ex.protocol}>{ex.protocol.toUpperCase()}</span></td>
                      <td className="mono">{ex.flow ? `${ex.flow.a} ⇄ ${ex.flow.b}` : '-'}</td>
                      <td className="mono">{formatReqSummary(ex)}</td>
                      <td className="mono">{formatResSummary(ex)}</td>
                      <td>{ex.request?.startTime ? new Date((ex.request.startTime)*1000).toISOString().split('T')[1].replace('Z','') : '-'}</td>
                      <td>{ex.timing?.rttMs!=null ? `${ex.timing.rttMs.toFixed(1)} ms` : '-'}</td>
                      <td>
                        {ex.request?.packetIds?.[0] && (
                          <button className="mini" title="Open request details" onClick={()=> openPacketDetails(ex.request!.packetIds[0])}>Req</button>
                        )}
                        {ex.response?.packetIds?.[0] && (
                          <button className="mini" title="Open response details" onClick={()=> openPacketDetails(ex.response!.packetIds[0])}>Resp</button>
                        )}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
              {exchanges.length === 0 && <div className="empty">No exchanges detected</div>}
            </section>
        )) : txnGrouped ? (
          <section className="table-wrap">
            <table className="table">
              <thead>
                <tr>
                  <th>Protocol</th>
                  <th>Key</th>
                  <th>Req/Resp</th>
                  <th>First</th>
                  <th>Last</th>
                  <th>Actions</th>
                </tr>
              </thead>
              <tbody>
                {txnGroups.flatMap((g) => ([
                  (
                    <tr key={`t-${g.key}`}>
                      <td><span className={'badge proto-' + g.proto.toLowerCase()}>{g.proto}</span></td>
                      <td className="mono">{g.label}</td>
                      <td>{g.req}/{g.resp}{g.other?` (+${g.other})`:''}</td>
                      <td>{g.first ? new Date(g.first*1000).toISOString().split('T')[1].replace('Z','') : '-'}</td>
                      <td>{g.last ? new Date(g.last*1000).toISOString().split('T')[1].replace('Z','') : '-'}</td>
                      <td>
                        <button className="mini" onClick={() => setTxnFocus(g.key)} title="View this transaction">View</button>
                        <button className="mini" onClick={() => setExpandedTxns((s)=>{const n=new Set(s); n.has(g.key)?n.delete(g.key):n.add(g.key); return n})}>{expandedTxns.has(g.key)?'Collapse':'Expand'}</button>
                        {exchanges.find(ex=> ex.id===g.key)?.request?.packetIds?.[0] && (
                          <button className="mini" onClick={() => openPacketDetails(exchanges.find(ex=> ex.id===g.key)!.request!.packetIds[0])} title="Open request details">Req</button>
                        )}
                        {exchanges.find(ex=> ex.id===g.key)?.response?.packetIds?.[0] && (
                          <button className="mini" onClick={() => openPacketDetails(exchanges.find(ex=> ex.id===g.key)!.response!.packetIds[0])} title="Open response details">Resp</button>
                        )}
                      </td>
                    </tr>
                  ),
                  expandedTxns.has(g.key) ? (
                    <tr key={`t-${g.key}-exp`} className="row-expansion">
                      <td colSpan={6}>
                        <div className="subtable">
                          <div className="subtable-title">Packets in {g.proto} transaction</div>
                          <table className="table">
                            <thead>
                              <tr>
                                <th>#</th>
                                <th>Time</th>
                                <th>Role</th>
                                <th>Length</th>
                                <th>Info</th>
                              </tr>
                            </thead>
                            <tbody>
                              {(exchanges.find(ex=> ex.id===g.key)?.request?.packetIds.concat(exchanges.find(ex=> ex.id===g.key)?.response?.packetIds || []) || [])
                                .slice(0,50)
                                .map((idx)=> {
                                  const p = rowByIndex.get(idx)
                                  if (!p) return null as any
                                  return (
                                    <tr key={p.index} style={{cursor:'pointer'}} onClick={()=> openPacketDetails(p.index)}>
                                      <td>{p.index}</td>
                                      <td>{p.ts ? new Date(p.ts * 1000).toISOString().split('T')[1].replace('Z','') : '-'}</td>
                                      <td>{p.txnRole || '-'}</td>
                                      <td>{p.capturedLen}</td>
                                      <td className="mono">{p.info}</td>
                                    </tr>
                                  )
                                })}
                            </tbody>
                          </table>
                        </div>
                      </td>
                    </tr>
                  ) : null,
                ]))}
              </tbody>
            </table>
            {txnGroups.length === 0 && <div className="empty">No transactions</div>}
          </section>
        ) : ipFocus && viewMode === 'grouped' ? (
          <section className="table-wrap">
            <table className="table">
              <thead>
                <tr>
                  <th>Peer IP</th>
                  <th>Count</th>
                  <th>Bytes</th>
                  <th>First</th>
                  <th>Last</th>
                  <th>Protocols</th>
                  <th>Actions</th>
                </tr>
              </thead>
              <tbody>
                {groups.flatMap((g) => ([
                  (
                    <tr key={`g-${g.peer}`}>
                      <td>{g.peer}</td>
                      <td>{g.count}</td>
                      <td>{g.bytes}</td>
                      <td>{isFinite(g.first) ? new Date(g.first * 1000).toISOString().split('T')[1].replace('Z','') : '-'}</td>
                      <td>{g.last ? new Date(g.last * 1000).toISOString().split('T')[1].replace('Z','') : '-'}</td>
                      <td>{g.protos.map((pr) => (
                        <span
                          key={pr}
                          className={'badge clickable proto-' + pr.toLowerCase()}
                          title={'Filter proto:' + pr.toLowerCase()}
                          onClick={() => toggleProto(pr)}
                        >{pr}</span>
                      ))}</td>
                      <td>
                        <button className="mini" onClick={() => { setPeerFocus(g.peer); setViewMode('list') }} title="View packets with this peer">View packets</button>
                        <button className="mini" onClick={() => setExpandedPeers((s)=>{const n=new Set(s); n.has(g.peer)?n.delete(g.peer):n.add(g.peer); return n})} title="Expand/collapse">{expandedPeers.has(g.peer)?'Collapse':'Expand'}</button>
                      </td>
                    </tr>
                  ),
                  expandedPeers.has(g.peer) ? (
                    <tr key={`g-${g.peer}-exp`} className="row-expansion">
                      <td colSpan={7}>
                        <div className="subtable">
                          <div className="subtable-title">Packets with {g.peer}</div>
                          <table className="table">
                            <thead>
                              <tr>
                                <th>#</th>
                                <th>Time</th>
                                <th>Protocol</th>
                                <th>Length</th>
                                <th>Info</th>
                              </tr>
                            </thead>
                            <tbody>
                              {filtered
                                .filter((p) => (ipFocusRole==='src'? p.dst===g.peer : ipFocusRole==='dst' ? p.src===g.peer : (p.src===g.peer || p.dst===g.peer)))
                                .slice(0, 50)
                                .map((p) => (
                                  <tr key={`${g.peer}-${p.index}`}>
                                    <td>{p.index}</td>
                                    <td>{p.ts ? new Date(p.ts * 1000).toISOString().split('T')[1].replace('Z','') : '-'}</td>
                                    <td><span className={'badge proto-' + ((p.proto||'').toLowerCase())}>{p.proto ?? '-'}</span></td>
                                    <td>{p.capturedLen}</td>
                                    <td className="mono">{p.info}</td>
                                  </tr>
                                ))}
                            </tbody>
                          </table>
                        </div>
                      </td>
                    </tr>
                  ) : null,
                ]))}
              </tbody>
            </table>
            {groups.length === 0 && (
              <div className="empty">No peers found</div>
            )}
          </section>
        ) : (
          collapsePairs ? (
            <section className="table-wrap">
              <table className="table">
                <thead>
                  <tr>
                    <th>Protocol</th>
                    <th>Flow</th>
                    <th>Request</th>
                    <th>Response</th>
                    <th>Start</th>
                    <th>RTT</th>
                    <th>Actions</th>
                  </tr>
                </thead>
                <tbody>
                  {exchanges.slice(0,1000).map((ex) => (
                    <tr key={ex.id}>
                      <td><span className={'badge proto-' + ex.protocol}>{ex.protocol.toUpperCase()}</span></td>
                      <td className="mono">{ex.flow ? `${ex.flow.a} ⇄ ${ex.flow.b}` : '-'}</td>
                      <td className="mono">{formatReqSummary(ex)}</td>
                      <td className="mono">{formatResSummary(ex)}</td>
                      <td>{ex.request?.startTime ? new Date((ex.request.startTime)*1000).toISOString().split('T')[1].replace('Z','') : '-'}</td>
                      <td>{ex.timing?.rttMs!=null ? `${ex.timing.rttMs.toFixed(1)} ms` : '-'}</td>
                      <td>
                        {ex.request?.packetIds?.[0] && (
                          <button className="mini" title="Open request details" onClick={()=> openPacketDetails(ex.request!.packetIds[0])}>Req</button>
                        )}
                        {ex.response?.packetIds?.[0] && (
                          <button className="mini" title="Open response details" onClick={()=> openPacketDetails(ex.response!.packetIds[0])}>Resp</button>
                        )}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
              {exchanges.length === 0 && <div className="empty">No exchanges detected</div>}
            </section>
          ) : (
            <section className="table-wrap">
              <table className="table">
              <thead>
                <tr>
                  <th>#</th>
                  <th>Time</th>
                  <th>Source</th>
                  <th>Destination</th>
                  <th>Protocol</th>
                  <th>Length</th>
                  <th>Info</th>
                </tr>
              </thead>
              <tbody>
                {filtered.slice(0, 5000).flatMap((p) => ([
                  (
                    <tr
                      key={p.index}
                      id={`row-${p.index}`}
                      className={selectedIndex === p.index ? 'sel' : ''}
                      onClick={() => setSelectedIndex(prev => prev === p.index ? null : p.index)}
                      onDoubleClick={() => {
                        const ex = exByPacket.get(p.index)
                        if (ex) setTxnFocus(ex.id)
                        else if (p.flowKey) setFlowKey(p.flowKey!)
                      }}
                    >
                      <td>{p.index}</td>
                      <td>{p.ts ? new Date(p.ts * 1000).toISOString().split('T')[1].replace('Z','') : '-'}</td>
                      <td>
                        {p.src ? (
                          <button className="link" onClick={(e) => { e.stopPropagation(); setIpFocus(p.src!); setIpFocusRole('src'); setViewMode('grouped'); setPeerFocus(null) }} title="Focus on this IP as Source">
                            {p.src}
                          </button>
                        ) : '-'}
                      </td>
                      <td>
                        {p.dst ? (
                          <button className="link" onClick={(e) => { e.stopPropagation(); setIpFocus(p.dst!); setIpFocusRole('dst'); setViewMode('grouped'); setPeerFocus(null) }} title="Focus on this IP as Destination">
                            {p.dst}
                          </button>
                        ) : '-'}
                      </td>
                      <td>
                        <span
                          className={'badge clickable proto-' + ((p.proto||'').toLowerCase())}
                          title={p.proto ? ('Filter proto:' + p.proto.toLowerCase()) : ''}
                          onClick={() => p.proto && toggleProto(p.proto)}
                        >{p.proto ?? '-'}</span>
                        {p.app && p.app.toUpperCase() !== (p.proto||'').toUpperCase() && (
                          <span
                            style={{marginLeft:6}}
                            className={'badge clickable proto-' + p.app.toLowerCase()}
                            title={'Filter proto:' + p.app.toLowerCase()}
                            onClick={() => toggleProto(p.app!)}
                          >{p.app}</span>
                        )}
                      </td>
                      <td>{p.capturedLen}</td>
                      <td className="mono">
                        {p.info}
                        <button className="mini" onClick={(e) => { e.stopPropagation(); setSelectedIndex(prev=> prev===p.index? null : p.index) }} title="Expand details">{selectedIndex===p.index?'Close':'Expand'}</button>
                        {p.flowKey && (
                          <button className="mini" onClick={(e) => { e.stopPropagation(); setFlowKey(p.flowKey!) }} title="Follow this flow">Follow</button>
                        )}
                      </td>
                    </tr>
                  ),
                  selectedIndex === p.index ? (
                    <tr key={`exp-${p.index}`} className="row-expansion">
                      <td colSpan={7}>
                        <div className="subtable">
                          <div className="subtable-title" style={{display:'flex', justifyContent:'space-between', alignItems:'center'}}>
                            <span>Packet {p.index} details</span>
                            <button className="mini" onClick={()=> setSelectedIndex(null)} title="Close">× Close</button>
                          </div>
                          <div className="details-grid">
                            <div>
                              <div className="details">
                                <div className="details-title">Summary</div>
                                <div className="mono" style={{whiteSpace:'pre-wrap'}}>{p.info}</div>
                                {p.app && (<div style={{marginTop:6}}>App: <span className={'badge proto-' + p.app.toLowerCase()}>{p.app}</span></div>)}
                              </div>
                              <div className="details" style={{marginTop:8}}>
                                <div className="details-title">Layers</div>
                                <div>L2: {p.src && p.dst ? '' : 'Ethernet'} {p.src ? '' : ''}</div>
                                <div>L3: {(p.proto||'').toUpperCase().startsWith('IP') ? p.proto : 'IP'} {p.src} → {p.dst}</div>
                                <div>L4: {p.srcPort!=null || p.dstPort!=null ? `${p.srcPort??''} → ${p.dstPort??''}` : '-'}</div>
                              </div>
                            </div>
                            <div>
                              <div className="details">
                                <div className="details-title">Hex (first 128B)</div>
                                <pre className="hex">{(()=>{
                                  const pkt = parsedRef.current?.packets[p.index-1]
                                  if (!pkt) return 'N/A'
                                  return hexPreview(pkt.data, 0, Math.min(128, pkt.data.length))
                                })()}</pre>
                              </div>
                              <div className="details" style={{marginTop:8}}>
                                <div className="details-title">Text (first 128B)</div>
                                <pre className="hex">{(()=>{
                                  const pkt = parsedRef.current?.packets[p.index-1]
                                  if (!pkt) return 'N/A'
                                  return textPreview(pkt.data, 0, Math.min(128, pkt.data.length))
                                })()}</pre>
                              </div>
                            </div>
                          </div>
                        </div>
                      </td>
                    </tr>
                  ) : null,
                ]) )}
              </tbody>
            </table>
            {filtered.length === 0 && (
              <div className="empty">No packets to display</div>
            )}
          </section>
          )
        )}
      </main>
      {streamKey && (
        <div className="modal" onClick={() => setStreamKey(null)}>
          <div className="modal-box" onClick={(e) => e.stopPropagation()}>
            <div className="modal-title">Stream {streamKey}</div>
            {streamPackets.length === 0 && <div className="empty">No payload captured</div>}
            {streamPackets.map((ch, i) => (
              <div key={i} className="stream-chunk">
                <div className="stream-dir">{ch.dir} · {new Date(ch.time*1000).toISOString().split('T')[1].replace('Z','')}</div>
                <pre className="stream-hex">{hexPreview(ch.data, 0, ch.data.length)}</pre>
              </div>
            ))}
            <div style={{display:'flex', justifyContent:'flex-end', marginTop:8}}>
              <button className="chip" onClick={() => setStreamKey(null)}>Close</button>
            </div>
          </div>
        </div>
      )}
      {/* Left side panel (icon toggles open/close) */}
      <LeftPanel open={sidePinned} onClose={() => setSidePinned(v=>!v)} tab={panelTab} setTab={setPanelTab} stats={stats as any} packet={selectedPacket} packetList={packets} selectedIndex={selectedIndex} onSelectIndex={(idx)=> setSelectedIndex(idx)} onProtoClick={(pr)=>toggleProto(pr)} onPortClick={(port: number)=> setFilter((prev)=> (prev? prev+ ' ' : '') + `port:${port}`)} width={sideWidth} onResize={(w)=> setSideWidth(w)} />
    </div>
  )
}

function formatReqSummary(ex: Exchange): string {
  if (ex.protocol === 'arp') {
    const s = ex.request?.summary
    const spa = s?.spa, tpa = s?.tpa
    return (spa && tpa) ? `who-has ${tpa} tell ${spa}` : 'who-has'
  }
  if (ex.protocol === 'dns') {
    const id = ex.request?.summary?.id
    return id!=null ? `id=${id}` : ''
  }
  if (ex.protocol === 'http1') {
    const s = ex.request?.summary
    return s ? `${s.method||''} ${s.path||''}`.trim() : ''
  }
  if (ex.protocol === 'tcp-unknown') {
    return `${ex.request?.summary?.bytes||0}B`
  }
  return ''
}
function formatResSummary(ex: Exchange): string {
  if (ex.protocol === 'arp') {
    const s = ex.response?.summary
    const spa = s?.spa, tpa = s?.tpa
    return (spa && tpa) ? `${tpa} is-at ${spa}` : 'is-at'
  }
  if (ex.protocol === 'dns') {
    const id = ex.response?.summary?.id
    return id!=null ? `id=${id}` : ''
  }
  if (ex.protocol === 'http1') {
    const s = ex.response?.summary
    return s && s.status ? `${s.status}` : ''
  }
  if (ex.protocol === 'tcp-unknown') {
    return `${ex.response?.summary?.bytes||0}B`
  }
  return ''
}

export default App
