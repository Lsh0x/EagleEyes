// Stats side panel

type Stats = {
  totalPackets: number
  totalBytes: number
  first: number | null
  last: number | null
  duration: number | null
  pps: number | null
  bps: number | null
  uniquePeers?: number
  protoList: { proto: string; count: number; bytes: number }[]
  topPeers: { peer: string; count: number; bytes: number }[]
  topTCP?: { port: number; count: number; bytes: number }[]
  topUDP?: { port: number; count: number; bytes: number }[]
  focus?: { inCount: number; outCount: number; inBytes: number; outBytes: number } | null
}

// Donut chart (SVG)
function Donut({ data, size=180, thickness=28 }: { data: { label: string; value: number; pct: number }[]; size?: number; thickness?: number }) {
  const r = (size/2) - 4
  const ir = r - thickness
  let a = -Math.PI/2
  const cx = size/2, cy = size/2
  const paths = data.map((s, i) => {
    const ang = s.pct * Math.PI*2
    const a0 = a, a1 = a + ang
    a = a1
    const x0 = cx + r*Math.cos(a0), y0 = cy + r*Math.sin(a0)
    const x1 = cx + r*Math.cos(a1), y1 = cy + r*Math.sin(a1)
    const xi0 = cx + ir*Math.cos(a0), yi0 = cy + ir*Math.sin(a0)
    const xi1 = cx + ir*Math.cos(a1), yi1 = cy + ir*Math.sin(a1)
    const large = ang > Math.PI ? 1 : 0
    const d = [
      `M ${x0} ${y0}`,
      `A ${r} ${r} 0 ${large} 1 ${x1} ${y1}`,
      `L ${xi1} ${yi1}`,
      `A ${ir} ${ir} 0 ${large} 0 ${xi0} ${yi0}`,
      'Z'
    ].join(' ')
    return <path key={i} d={d} fill={sliceColor(s.label)} stroke="#0b0f14" strokeWidth={1} />
  })
  return (
    <svg width={size} height={size} viewBox={`0 0 ${size} ${size}`}>
      <g>{paths}</g>
      <circle cx={cx} cy={cy} r={ir} fill="transparent" />
    </svg>
  )
}

function sliceColor(label: string): string {
  const m: Record<string,string> = {
    TCP:'#2a2038', UDP:'#1d2f1d', DNS:'#362b1c', ARP:'#3a1f1f', ICMP:'#2b2b2b', ICMPV4:'#2b2b2b', ICMPV6:'#2b2b2b', ETH:'#22314a', RTP:'#22314a', RTCP:'#22314a', OTHER:'#3b4657'
  }
  if (m[label]) return m[label]
  // hash to hsl
  let h=0; for (let i=0;i<label.length;i++) h = (h*31 + label.charCodeAt(i)) % 360
  return `hsl(${h} 45% 32%)`
}

function bytes(n: number) {
  if (n < 1024) return `${n} B`
  if (n < 1024 * 1024) return `${(n/1024).toFixed(1)} KB`
  return `${(n/1024/1024).toFixed(1)} MB`
}
function rate(n: number | null) {
  if (n == null) return '-'
  if (n < 1000) return `${n.toFixed(1)}`
  if (n < 1000*1000) return `${(n/1000).toFixed(1)}k`
  return `${(n/1000/1000).toFixed(2)}M`
}

export default function StatsPanel({ stats, onProtoClick, onPortClick }: { stats: Stats; onProtoClick?: (proto: string) => void; onPortClick?: (port: number, proto: 'TCP'|'UDP') => void }) {
  const dur = stats.duration ? `${stats.duration.toFixed(2)}s` : '-'
  const first = stats.first ? new Date(stats.first*1000).toISOString().split('T')[1].replace('Z','') : '-'
  const last = stats.last ? new Date(stats.last*1000).toISOString().split('T')[1].replace('Z','') : '-'
  const maxBytes = Math.max(1, ...stats.protoList.map(x=>x.bytes))

  // Build pie data (top 8 by bytes + other)
  const pie = (() => {
    const arr = [...stats.protoList].sort((a,b)=> b.bytes - a.bytes)
    const top = arr.slice(0, 8)
    const restBytes = Math.max(0, arr.slice(8).reduce((s,x)=>s+x.bytes,0))
    if (restBytes > 0) top.push({ proto: 'OTHER', count: 0, bytes: restBytes } as any)
    const total = Math.max(1, top.reduce((s,x)=> s + x.bytes, 0))
    return top.map(x => ({ label: x.proto, value: x.bytes, pct: x.bytes/total }))
  })()

  return (
    <div>
      <div style={{display:'flex', justifyContent:'space-between', alignItems:'center', marginBottom:8}}>
        <div style={{fontWeight:700}}>Stats</div>
        <div className="mono" style={{color:'#9fb1c1'}}>
          {stats.totalPackets} pkts · {bytes(stats.totalBytes)}{stats.duration? ` · ${stats.duration.toFixed(2)}s` : ''}
        </div>
      </div>
      {/* Pie (camembert) of protocols by bytes */}
      <div style={{display:'flex', gap:12, alignItems:'center', marginBottom:12}}>
        <Donut data={pie} size={180} thickness={28} />
        <div style={{display:'grid', gridAutoRows:'min-content', rowGap:6}}>
          {pie.map((s, i)=> (
            <div key={i} style={{display:'flex', alignItems:'center', gap:8}}>
              <span style={{display:'inline-block', width:12, height:12, borderRadius:3, background: sliceColor(s.label)}} />
              <span className={'badge'} style={{background:'transparent', border:'1px solid #2d3643', color:'#c2d3f2'}}>{s.label}</span>
              <span className="mono" style={{color:'#9fb1c1'}}>{(s.pct*100).toFixed(1)}%</span>
            </div>
          ))}
        </div>
      </div>

      <div className="details" style={{marginBottom:12}}>
        <div className="details-grid">
          <div>
            <div className="details-title">Capture</div>
            <div>Packets: {stats.totalPackets}</div>
            <div>Bytes: {bytes(stats.totalBytes)}</div>
            <div>Duration: {dur}</div>
            <div>First: {first}</div>
            <div>Last: {last}</div>
            <div>Peers: {stats.uniquePeers ?? '-'}</div>
          </div>
          <div>
            <div className="details-title">Rates</div>
            <div>PPS: {rate(stats.pps)}</div>
            <div>BPS: {stats.bps != null ? rate(stats.bps) + ' b/s' : '-'}</div>
            {stats.focus && (
              <div style={{marginTop:6, color:'#9fb1c1'}}>
                <div className="details-title">Focus I/O</div>
                <div>In: {stats.focus.inCount} · {bytes(stats.focus.inBytes)}</div>
                <div>Out: {stats.focus.outCount} · {bytes(stats.focus.outBytes)}</div>
              </div>
            )}
          </div>
        </div>
      </div>

    <div className="details" style={{marginBottom:12}}>
      <div className="details-title">Protocols</div>
      {stats.protoList.slice(0,20).map((p)=> {
        const pct = stats.totalBytes > 0 ? (100 * p.bytes / stats.totalBytes) : 0
        return (
        <div key={p.proto} style={{display:'flex', alignItems:'center', gap:8, margin:'6px 0'}}>
          <span
            className={'badge clickable proto-' + p.proto.toLowerCase()}
            style={{minWidth:64,textAlign:'center'}}
            title={onProtoClick ? `Filter proto:${p.proto.toLowerCase()}` : undefined}
            onClick={() => onProtoClick && onProtoClick(p.proto)}
          >{p.proto}</span>
          <div className="mono" style={{color:'#9fb1c1', minWidth:160}}>{p.count} · {bytes(p.bytes)} · {pct.toFixed(1)}%</div>
          <div
            style={{flex:1, background:'#0b0f14', border:'1px solid #1f2630', height:10, borderRadius:6, overflow:'hidden', cursor: onProtoClick? 'pointer':'default'}}
            onClick={() => onProtoClick && onProtoClick(p.proto)}
            title={onProtoClick ? `Filter proto:${p.proto.toLowerCase()}` : undefined}
          >
            <div style={{ width: `${Math.max(4, Math.round(100*p.bytes/maxBytes))}%`, height:'100%', background:'#1f6feb' }} />
          </div>
        </div>
      )})}
    </div>

      <div className="details" style={{marginBottom:12}}>
        <div className="details-title">Top ports</div>
        <div className="details-grid">
          <div>
            <div className="details-title">TCP</div>
            <table className="table" style={{fontSize:13}}>
              <thead><tr><th>Port</th><th>Pkts</th><th>Bytes</th></tr></thead>
              <tbody>
                {stats.topTCP?.map((t:any)=>(
                  <tr key={`t${t.port}`}>
                    <td><button className="link" onClick={()=>onPortClick && onPortClick(t.port,'TCP')}>:{t.port}</button></td>
                    <td>{t.count}</td>
                    <td>{bytes(t.bytes)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          <div>
            <div className="details-title">UDP</div>
            <table className="table" style={{fontSize:13}}>
              <thead><tr><th>Port</th><th>Pkts</th><th>Bytes</th></tr></thead>
              <tbody>
                {stats.topUDP?.map((t:any)=>(
                  <tr key={`u${t.port}`}>
                    <td><button className="link" onClick={()=>onPortClick && onPortClick(t.port,'UDP')}>:{t.port}</button></td>
                    <td>{t.count}</td>
                    <td>{bytes(t.bytes)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      </div>

      <div className="details">
        <div className="details-title">Top talkers</div>
        <table className="table" style={{fontSize:13}}>
          <thead>
            <tr>
              <th>IP</th>
              <th>Packets</th>
              <th>Bytes</th>
            </tr>
          </thead>
          <tbody>
            {stats.topPeers.map((t)=> (
              <tr key={t.peer}>
                <td className="mono">{t.peer}</td>
                <td>{t.count}</td>
                <td>{bytes(t.bytes)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  )
}
