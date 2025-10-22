import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import './App.css'

import { parseCapture } from './lib/parsers'
import { decodePacket, extractL4Payload } from './lib/decoders'
import LeftPanel from './components/LeftPanel'

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

  const onFiles = useCallback(async (files: FileList | null) => {
    setError(null)
    setPackets([])
    if (!files || files.length === 0) return
    const f = files[0]
    setFileName(f.name)
    try {
      const buf = await f.arrayBuffer()
      const parsed = parseCapture(buf)
      parsedRef.current = parsed
      setPackets(
        parsed.packets.map((p, i) => {
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
      arr = arr.filter((p) => p.txnKey === txnFocus)
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
      arr = arr.filter((p) => selectedProtos.has((p.proto || '').toUpperCase()))
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
    let arr = packets
    if (flowKey) arr = arr.filter((p) => p.flowKey === flowKey)
    if (ipFocus) {
      if (ipFocusRole === 'src') arr = arr.filter((p) => p.src === ipFocus)
      else if (ipFocusRole === 'dst') arr = arr.filter((p) => p.dst === ipFocus)
      else arr = arr.filter((p) => p.src === ipFocus || p.dst === ipFocus)
    }
    if (selectedProtos.size > 0) arr = arr.filter((p) => selectedProtos.has((p.proto || '').toUpperCase()))
    if (filter.trim()) {
      const tokens = filter.trim().split(/\s+/)
      arr = arr.filter((p) => tokens.every((t) => matchToken(p, t)))
    }
    const map = new Map<string, { proto: string; req: number; resp: number; other: number; first: number; last: number }>()
    for (const p of arr) {
      if (!p.txnKey || !p.proto) continue
      const g = map.get(p.txnKey) || { proto: p.proto, req: 0, resp: 0, other: 0, first: Number.POSITIVE_INFINITY, last: 0 }
      if (p.txnRole === 'request' || p.txnRole === 'query' || p.txnRole === 'syn') g.req++
      else if (p.txnRole === 'response' || p.txnRole === 'syn-ack' || p.txnRole === 'ack') g.resp++
      else g.other++
      g.first = Math.min(g.first, p.ts || Number.POSITIVE_INFINITY)
      g.last = Math.max(g.last, p.ts || 0)
      map.set(p.txnKey, g)
    }
    const out = Array.from(map.entries()).map(([key, v]) => ({ key, proto: v.proto, label: key, req: v.req, resp: v.resp, other: v.other, first: v.first, last: v.last }))
    // Sort by time
    out.sort((a, b) => (a.first || 0) - (b.first || 0))
    return out
  }, [txnGrouped, packets, flowKey, ipFocus, ipFocusRole, selectedProtos, filter])

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

      <main className="content">
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
        </section>

        <section className="toolbar">
          <div className="toolbar-top">
            <input
              className="input"
              placeholder="Filter: free text or proto:tcp ip:1.2.3.4 port:53 len:>100"
              value={filter}
              onChange={(e) => setFilter(e.target.value)}
            />
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

        {txnGrouped ? (
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
                              {filtered.filter(p=>p.txnKey===g.key).slice(0,50).map(p=> (
                                <tr key={p.index}>
                                  <td>{p.index}</td>
                                  <td>{p.ts ? new Date(p.ts * 1000).toISOString().split('T')[1].replace('Z','') : '-'}</td>
                                  <td>{p.txnRole || '-'}</td>
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
              {filtered.slice(0, 5000).map((p) => (
                <tr
                  key={p.index}
                  id={`row-${p.index}`}
                  className={selectedIndex === p.index ? 'sel' : ''}
                  onClick={() => setSelectedIndex(p.index)}
                  onDoubleClick={() => p.flowKey && setFlowKey(p.flowKey!)}
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
                  <td><span
                    className={'badge clickable proto-' + ((p.proto||'').toLowerCase())}
                    title={p.proto ? ('Filter proto:' + p.proto.toLowerCase()) : ''}
                    onClick={() => p.proto && toggleProto(p.proto)}
                  >{p.proto ?? '-'}</span></td>
                  <td>{p.capturedLen}</td>
                  <td className="mono">
                    {p.info}
                    {p.flowKey && (
                      <button className="mini" onClick={(e) => { e.stopPropagation(); setFlowKey(p.flowKey!) }} title="Follow this flow">Follow</button>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
          {filtered.length === 0 && (
            <div className="empty">No packets to display</div>
          )}
        </section>
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
      {/* Left side panel with tabs */}
      <LeftPanel open={true} onClose={() => {}} tab={panelTab} setTab={setPanelTab} stats={stats as any} packet={selectedPacket} packetList={packets} selectedIndex={selectedIndex} onSelectIndex={(idx)=> setSelectedIndex(idx)} onProtoClick={(pr)=>toggleProto(pr)} onPortClick={(port: number)=> setFilter((prev)=> (prev? prev+ ' ' : '') + `port:${port}`)} />
    </div>
  )
}

export default App
