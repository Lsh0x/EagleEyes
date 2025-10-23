import StatsPanel from './StatsPanel'
import type { Decoded } from '../lib/decoders'

type MiniPacket = { index: number; proto?: string; info?: string }

export default function LeftPanel({
  open,
  onClose,
  tab,
  // setTab (unused when always showing stats)
  stats,
  packet,
  packetList,
  selectedIndex,
  onSelectIndex,
  onProtoClick,
  onPortClick,
  width,
  onResize,
}: {
  open: boolean
  onClose: () => void
  tab: 'packet' | 'stats'
  setTab: (t: 'packet' | 'stats') => void
  stats: any
  packet: { dec: Decoded; hex: string } | null
  packetList?: MiniPacket[]
  selectedIndex?: number | null
  onSelectIndex?: (index: number) => void
  onProtoClick?: (proto: string) => void
  onPortClick?: (port: number, proto: 'TCP'|'UDP') => void
  width?: number
  onResize?: (w: number) => void
}) {
  function startDrag(e: React.MouseEvent) {
    if (!onResize) return
    e.preventDefault()
    const startX = e.clientX
    const startW = width || 320
    const minW = 260, maxW = 560
    function onMove(ev: MouseEvent) {
      const next = Math.max(minW, Math.min(maxW, startW + (ev.clientX - startX)))
      onResize && onResize(next)
    }
    function onUp() {
      window.removeEventListener('mousemove', onMove)
      window.removeEventListener('mouseup', onUp)
    }
    window.addEventListener('mousemove', onMove)
    window.addEventListener('mouseup', onUp)
  }

  return (
    <div className={'side-panel ' + (open ? 'open' : '')} role="complementary" aria-label="Statistics panel" style={open && width ? { width } : undefined}>
      <button className="side-toggle" onClick={() => onClose()} title={open? 'Collapse' : 'Expand'}>{open ? '◀' : '▶'}</button>
      {open && (
        <div className="side-resizer" onMouseDown={startDrag} title="Drag to resize" />
      )}
      <div className="side-content">
        <div className="details-title" style={{marginBottom:8}}>Stats</div>
        <StatsPanel stats={stats} onProtoClick={onProtoClick} onPortClick={onPortClick} />
        <div className="details" style={{marginTop:12}}>
          <div className="details-title">Packets</div>
          <div style={{maxHeight: 260, overflow:'auto'}}>
            <table className="table" style={{fontSize:12}}>
              <thead><tr><th>#</th><th>Proto</th><th>Info</th></tr></thead>
              <tbody>
                {packetList?.slice(0,200).map((p)=> (
                  <tr key={p.index} className={selectedIndex===p.index?'sel':''} style={{cursor:'pointer'}} onClick={()=> onSelectIndex && onSelectIndex(p.index)}>
                    <td>{p.index}</td>
                    <td><span className={'badge proto-' + ((p.proto||'').toLowerCase())}>{p.proto||'-'}</span></td>
                    <td className="mono">{p.info||''}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
        {tab === 'packet' ? (
          packet ? (
            <div className="details">
              <div className="details-grid">
                <div>
                  <div className="details-title">Details</div>
                  <div>Src IP: {packet.dec.l3?.src || '-'}</div>
                  <div>Dst IP: {packet.dec.l3?.dst || '-'}</div>
                  <div>Src MAC: {packet.dec.l2?.srcMac || '-'}</div>
                  <div>Dst MAC: {packet.dec.l2?.dstMac || '-'}</div>
                  <div>L4: {packet.dec.l4?.proto} {packet.dec.l4?.srcPort ?? ''} → {packet.dec.l4?.dstPort ?? ''} {packet.dec.l4?.tcpFlags ? `[${packet.dec.l4.tcpFlags}]` : ''}</div>
                  {packet.dec.meta?.dns && (
                    <div>
                      {(packet.dec.meta.dns.qr ? 'DNSR' : 'DNSQ')}: {packet.dec.meta.dns.name || '(no-name)'}{packet.dec.meta.dns.qtypeName ? ' ' + packet.dec.meta.dns.qtypeName : ''}|{packet.dec.meta.dns.id}
                    </div>
                  )}
                  {packet.dec.meta?.arp && (<div>ARP: op={packet.dec.meta.arp.op} {packet.dec.meta.arp.spa} → {packet.dec.meta.arp.tpa}</div>)}
                </div>
                <div>
                  <div className="details-title">Payload (first 64B)</div>
                  <pre className="hex">{packet.hex}</pre>
                </div>
              </div>
            </div>
          ) : (
            <div className="empty">No packet selected</div>
          )
        ) : (
          <StatsPanel stats={stats} onProtoClick={onProtoClick} onPortClick={onPortClick} />
        )}
      </div>
    </div>
  )
}
