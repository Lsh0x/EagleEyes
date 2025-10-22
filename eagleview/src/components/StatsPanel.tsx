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
  return (
    <div>
      <div style={{display:'flex', justifyContent:'space-between', alignItems:'center', marginBottom:8}}>
        <div style={{fontWeight:700}}>Stats</div>
        <div className="mono" style={{color:'#9fb1c1'}}>
          {stats.totalPackets} pkts · {bytes(stats.totalBytes)}{stats.duration? ` · ${stats.duration.toFixed(2)}s` : ''}
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
