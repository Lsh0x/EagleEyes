import StatsPanel from './StatsPanel'
import type { Decoded } from '../lib/decoders'

export default function LeftPanel({
  open,
  onClose,
  tab,
  setTab,
  stats,
  packet,
  onProtoClick,
}: {
  open: boolean
  onClose: () => void
  tab: 'packet' | 'stats'
  setTab: (t: 'packet' | 'stats') => void
  stats: any
  packet: { dec: Decoded; hex: string } | null
  onProtoClick?: (proto: string) => void
}) {
  return (
    <div className={'side-panel ' + (open ? 'open' : '')}>
      <div className="side-tabs">
        <button className={'side-tabbtn ' + (tab==='packet'?'active':'')} onClick={() => setTab('packet')}>Packet</button>
        <button className={'side-tabbtn ' + (tab==='stats'?'active':'')} onClick={() => setTab('stats')}>Stats</button>
        <div style={{flex:1}} />
        <button className="chip" onClick={onClose}>Close</button>
      </div>

      {tab === 'packet' ? (
        packet ? (
          <div className="details">
            <div className="details-grid">
              <div>
                <div className="details-title">Details</div>
                <div>L2: {packet.dec.l2?.srcMac} → {packet.dec.l2?.dstMac}</div>
                <div>L3: {packet.dec.l3?.proto} {packet.dec.l3?.src} → {packet.dec.l3?.dst}</div>
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
        <StatsPanel stats={stats} onClose={onClose} onProtoClick={onProtoClick} />
      )}
    </div>
  )
}
