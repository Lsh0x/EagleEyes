import { useEffect, useMemo, useRef, useState } from 'react'

// Lightweight bottom-right chatbot powered by WebLLM (in-browser, no API key)
// It suggests EagleView filters only (no Wireshark/TShark display filters).

// We import lazily to avoid bundling cost on first paint.
let webllm: typeof import('@mlc-ai/web-llm') | null = null

export type FilterChatbotProps = {
  onApplyFilter?: (filter: string) => void
  contextHint?: string
}

const FAST_MODEL_ID = 'Llama-3.2-1B-Instruct-q4f32_1-MLC'
const BAL_MODEL_ID = 'Llama-3.2-3B-Instruct-q4f32_1-MLC'

function SystemPrompt(hint?: string) {
  const guide = `You are Filter Assistant for EagleView packet analyzer. Give ONLY valid EagleView filters.

CRITICAL RULES:
1. "all IPv4" or "IPv4 traffic" → answer ONLY: ipv4
2. "all IPv6" or "IPv6 traffic" → answer ONLY: ipv6  
3. "all ARP" or "ARP packets" → answer ONLY: arp
4. "TCP SYN" → answer ONLY: tcp.syn
5. "HTTPS" or "port 443" → answer ONLY: port:443
6. Use ip:<addr> ONLY when user gives a SPECIFIC IP address (e.g. "show me 192.168.1.1")
7. NEVER add example IPs like 192.168.1.100 unless the user mentions that exact IP
8. Space = AND, || = OR, && = explicit AND

Valid EagleView tokens:
- Protocols: ipv4, ipv6, arp, tcp, udp, dns
- TCP flags: tcp.syn, tcp.ack, tcp.fin, tcp.rst
- IP filters: ip:<addr>, src:<addr>, dst:<addr>
- MAC filters: mac:<xx:xx:..>, srcmac:<mac>, dstmac:<mac>
- Port: port:<number>
- Other: dns.id:<n>, arp.op:<request|reply|1|2>, len:<op><n>

Response format:
- Output the filter on its own line (in backticks or code fence)
- Add brief explanation after
- NO Wireshark syntax (no ==, no frame.len, no ip.addr)
- NO CIDR notation (/24)
- NO made-up fields

Examples:
Q: "show all IPv4 packets"
A: \`ipv4\`
Shows all IPv4 traffic.

Q: "TCP SYN packets"
A: \`tcp.syn\`
Shows TCP packets with SYN flag set.

Q: "traffic to 8.8.8.8"
A: \`dst:8.8.8.8\`
Shows packets going to 8.8.8.8.

Q: "HTTPS traffic"
A: \`tcp port:443\`
Shows TCP traffic on port 443.

Q: "DNS or ARP"
A: \`dns || arp\`
Shows either DNS or ARP packets.
${hint ? `
Context: ${hint}` : ''}`
  return guide
}

export default function FilterChatbot({ onApplyFilter, contextHint }: FilterChatbotProps) {
  const [open, setOpen] = useState(false)
  const [progress, setProgress] = useState<number>(0)
  const [ready, setReady] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [input, setInput] = useState('')
  const [messages, setMessages] = useState<{ role: 'user'|'assistant'; content: string }[]>([])
  const [mode, setMode] = useState<'auto'|'local'>('auto')
  const [modelId, setModelId] = useState<string>(FAST_MODEL_ID)
  const engineRef = useRef<Awaited<ReturnType<NonNullable<typeof webllm>['CreateMLCEngine']>> | null>(null)
  const scrollRef = useRef<HTMLDivElement | null>(null)
  const [selectedEVs, setSelectedEVs] = useState<Set<string>>(new Set())
  const [combineMode, setCombineMode] = useState<'or'|'and'>('or')

  // Build a short context hint users can pass from parent
  const sys = useMemo(()=> SystemPrompt(contextHint), [contextHint])

  async function initEngine(currentMode: 'auto'|'local', currentModelId: string) {
    setReady(false)
    setError(null)
    setProgress(0)
    if (!webllm) webllm = await import('@mlc-ai/web-llm')
    const opts: any = {
      initProgressCallback: (p: any) => setProgress(Math.round(((p?.progress||0)*100))),
    }
    if (currentMode === 'local') {
      opts.appConfig = { model_list: [{ model_id: currentModelId, model_url: `/models/webllm/${currentModelId}` }] }
    }
    const engine = await webllm!.CreateMLCEngine(currentModelId, opts)
    engineRef.current = engine
    setReady(true)
  }

  useEffect(() => {
    let cancelled = false
    ;(async () => {
      try {
        await initEngine(mode, modelId)
      } catch (e: any) {
        if (cancelled) return
        setError(e?.message || 'Failed to init WebLLM (WebGPU required).')
      }
    })()
    return () => { cancelled = true }
  }, [mode, modelId])

  async function send() {
    const text = input.trim()
    if (!text || !engineRef.current) return
    setInput('')
    const userMsg = { role: 'user' as const, content: text }
    setMessages((m) => [...m, userMsg])
    try {
      const stream = await engineRef.current.chat.completions.create({
        messages: [
          { role: 'system', content: sys },
          ...messages,
          userMsg,
        ],
        temperature: 0.1,
        max_tokens: 200,
        stream: true,
      })
      let acc = ''
      setMessages((m)=> [...m, { role: 'assistant', content: '' }])
      for await (const chunk of stream as any) {
        const delta = chunk?.choices?.[0]?.delta?.content || ''
        if (delta) {
          acc += delta
          setMessages((m)=> {
            const n = [...m]
            n[n.length-1] = { role: 'assistant', content: acc }
            return n
          })
        }
      }
    } catch (e: any) {
      setError(e?.message || 'Generation failed')
    }
  }

  function isLikelyEvToken(tok: string): boolean {
    // Allowed tokens: bare protos, field:value pairs, tcp flags, len comparisons
    const t = tok.trim()
    if (!t) return false
    // Bare protocol names
    if (/^(arp|tcp|udp|dns|ipv4|ipv6)$/i.test(t)) return true
    // TCP flags
    if (/^tcp\.(syn|ack|fin|rst)$/i.test(t)) return true
    // Field:value patterns (no whitespace in values for IPs/MACs/numbers)
    if (/^(ip|host|src|dst):\S+$/i.test(t)) return true
    if (/^(mac|srcmac|dstmac):[0-9a-f:]+$/i.test(t)) return true
    if (/^port:\d+$/i.test(t)) return true
    if (/^dns\.id:\d+$/i.test(t)) return true
    if (/^arp\.op:(request|reply|\d+)$/i.test(t)) return true
    if (/^len:[><=]+\d+$/i.test(t)) return true
    return false
  }
  
  function isLikelyEvFilter(line: string): boolean {
    const s = line.trim()
    if (!s) return false
    // Reject common Wireshark operators
    if (/[=]{2}|&&|\bframe\.len\b|\bip\.addr\b|\btcp\.port\b/.test(s)) return false
    const tokens = s.split(/\s+/)
    return tokens.every(isLikelyEvToken)
  }
  
  function splitOrCandidates(s: string): string[] {
    // If a line includes OR-style separators, split into individual EVs
    const parts = s.split(/\s*(?:\|\||\||\bor\b)\s*/i).map(x=>x.trim()).filter(Boolean)
    return parts.length > 1 ? parts : [s]
  }
  
  function sanitizeCandidate(line: string): string {
    let s = line.trim()
    // Remove code fences/backticks around single-line
    s = s.replace(/^`+|`+$/g, '')
    // Remove leading bullets/numbering and optional EV label
    s = s.replace(/^(?:[-*•]\s+|\d+[.)]\s+|EV\s*[:\-]\s*)/i, '')
    return s.trim()
  }
  
  function collectTextCandidates(text: string): string[] {
    const cands: string[] = []
    // 1) Fenced code blocks
    const fenceRe = /```[a-zA-Z0-9_-]*\n([\s\S]*?)```/g
    let m: RegExpExecArray | null
    while ((m = fenceRe.exec(text)) != null) {
      const body = m[1] || ''
      cands.push(...body.split(/\n+/).map(l=>l.trim()).filter(Boolean))
    }
    // 2) Inline code
    const inlineRe = /`([^`]+)`/g
    while ((m = inlineRe.exec(text)) != null) {
      cands.push((m[1] || '').trim())
    }
    // 3) Plain lines
    cands.push(...text.split(/\n+/).map(l=>l.trim()).filter(Boolean))
    return cands
  }
  
  function extractEvFilters(text: string): string[] {
    const raw = collectTextCandidates(text)
    const out: string[] = []
    for (const line of raw) {
      const sanitized = sanitizeCandidate(line)
      for (const piece of splitOrCandidates(sanitized)) {
        const p = sanitizeCandidate(piece)
        if (isLikelyEvFilter(p)) out.push(p)
      }
    }
    // De-duplicate while preserving order
    const seen = new Set<string>()
    return out.filter(x=>{ if (seen.has(x)) return false; seen.add(x); return true })
  }
  
  function extractEvFilter(text: string): string | null {
    const all = extractEvFilters(text)
    return all[0] || null
  }

  // Auto-scroll to bottom when near-bottom and new messages arrive or when opening
  useEffect(() => {
    if (!open) return
    const sc = scrollRef.current
    if (!sc) return
    const nearBottom = (sc.scrollHeight - sc.scrollTop - sc.clientHeight) < 80
    if (nearBottom) sc.scrollTop = sc.scrollHeight
  }, [messages, open])

  useEffect(() => {
    if (open) {
      const sc = scrollRef.current
      if (sc) sc.scrollTop = sc.scrollHeight
    }
  }, [open])

  return (
    <>
      <button
        aria-label="Open Filter Assistant"
        style={{ position:'fixed', right:24, bottom:24, width:64, height:64, borderRadius:32, background:'#0b72e7', color:'#fff', border:'none', boxShadow:'0 8px 24px rgba(0,0,0,.2)', cursor:'pointer', zIndex:1000, fontSize:24 }}
        onClick={()=> setOpen(v=>!v)}
        title="Filter Assistant"
      >💬</button>

      {open && (
        <div style={{ position:'fixed', right:24, bottom:100, width:480, maxHeight:'85vh', background:'#fff', border:'1px solid #e5e7eb', borderRadius:12, boxShadow:'0 12px 36px rgba(0,0,0,.2)', display:'flex', flexDirection:'column', overflow:'hidden', zIndex:1000 }}>
          <div style={{ padding:'10px 12px', background:'#0b72e7', color:'#fff', fontWeight:600, display:'flex', alignItems:'center', justifyContent:'space-between', gap:8 }}>
            <span>Filter Assistant {ready? '' : `· ${progress}%`}</span>
            <div style={{display:'flex', gap:6, alignItems:'center'}}>
              <label style={{fontSize:12}}>Model</label>
              <select value={modelId} onChange={(e)=> setModelId(e.target.value)} style={{fontSize:12, padding:'4px 6px', borderRadius:6, border:'1px solid #e5e7eb'}}>
                <option value={FAST_MODEL_ID}>Fast (1B)</option>
                <option value={BAL_MODEL_ID}>Balanced (3B)</option>
              </select>
              <select value={mode} onChange={(e)=> setMode(e.target.value as any)} style={{fontSize:12, padding:'4px 6px', borderRadius:6, border:'1px solid #e5e7eb'}} title="Load from CDN or local assets">
                <option value="auto">Auto</option>
                <option value="local">Local</option>
              </select>
              <label style={{fontSize:12, marginLeft:6}}>Combine</label>
              <select value={combineMode} onChange={(e)=> setCombineMode(e.target.value as any)} style={{fontSize:12, padding:'4px 6px', borderRadius:6, border:'1px solid #e5e7eb'}} title="How to combine selected filters">
                <option value="or">OR (||)</option>
                <option value="and">AND (&&)</option>
              </select>
            </div>
          </div>
          <div ref={scrollRef} style={{ padding:12, overflow:'auto', display:'flex', flexDirection:'column', gap:8 }}>
            {!ready && !error && (<div>Loading local model… {progress}%</div>)}
            {error && (
              <div style={{color:'#b91c1c', display:'flex', flexDirection:'column', gap:8}}>
                <div>Error: {error}</div>
                <div style={{fontSize:12,color:'#991b1b'}}>Tip: This often happens when the browser blocks caching CDN model files. You can self-host the model to keep everything local.</div>
                <div style={{display:'flex', gap:8, flexWrap:'wrap'}}>
                  <button onClick={()=> initEngine(mode, modelId).catch(e=> setError(e?.message||'Init failed'))} style={{padding:'6px 10px', border:'1px solid #e5e7eb', borderRadius:8, background:'#fff', cursor:'pointer'}}>Retry</button>
                  <button onClick={()=> setMode('local')} style={{padding:'6px 10px', border:'1px solid #e5e7eb', borderRadius:8, background:'#fff', cursor:'pointer'}}>Try local assets</button>
                </div>
                <details>
                  <summary style={{cursor:'pointer'}}>How to self-host model (one-time)</summary>
                  <ol style={{margin:'6px 0 0 16px', fontSize:12}}>
                    <li>Download the chosen model folder (<code>{modelId}</code>) from the WebLLM models repo.</li>
                    <li>Place it under <code>public/models/webllm/{modelId}</code> of this app.</li>
                    <li>Reload. The assistant will use local assets automatically.</li>
                  </ol>
                </details>
              </div>
            )}
            {messages.map((m, i)=> {
              const isUser = m.role==='user'
              const evs = !isUser ? extractEvFilters(m.content) : []
              return (
                <div key={i} style={{ alignSelf: isUser?'flex-end':'flex-start', maxWidth:'80%' }}>
                  <div style={{ background: isUser?'#e6f0ff':'#f3f4f6', color:'#0f172a', padding:'8px 10px', borderRadius:10, whiteSpace:'pre-wrap' }}>
                    {m.content}
                  </div>
                  {!isUser && evs.length>0 && onApplyFilter && (
                    <div style={{ display:'flex', flexWrap:'wrap', gap:6, marginTop:6 }}>
                      {evs.map((f, j) => {
                        const active = selectedEVs.has(f)
                        return (
                          <span
                            key={j}
                            onClick={()=> {
                              const next = new Set(selectedEVs)
                              if (next.has(f)) next.delete(f); else next.add(f)
                              setSelectedEVs(next)
                              const joiner = combineMode==='or' ? ' || ' : ' && '
                              const expr = Array.from(next).join(joiner)
                              if (expr && onApplyFilter) onApplyFilter(expr)
                            }}
                            title={active?`Remove: ${f}`:`Add: ${f}`}
                            style={{
                              fontFamily:'ui-monospace, SFMono-Regular, Menlo, monospace',
                              fontSize:12,
                              padding:'4px 6px',
                              border:'1px solid '+(active?'#0b72e7':'#e5e7eb'),
                              color: active? '#0b72e7':'#0f172a',
                              background: active? '#e6f0ff':'#fff',
                              borderRadius:6,
                              cursor:'pointer',
                              userSelect:'none'
                            }}
                          >{f}</span>
                        )
                      })}
                    </div>
                  )}
                </div>
              )
            })}
          </div>
          <div style={{ padding:'8px 12px', borderTop:'1px solid #e5e7eb', display:'flex', gap:6, alignItems:'center' }}>
            <input
              placeholder="Ask for a filter or explain a packet…"
              value={input}
              onChange={e=> setInput(e.target.value)}
              onKeyDown={(e)=> { if (e.key==='Enter') send() }}
              style={{ flex:1, padding:'9px 10px', border:'1px solid #e5e7eb', borderRadius:8, outline:'none' }}
              disabled={!ready}
            />
            <button onClick={send} disabled={!ready || !input.trim()} style={{ padding:'9px 12px', background:'#0b72e7', color:'#fff', border:'none', borderRadius:8, cursor:'pointer' }}>Send</button>
            {onApplyFilter && (()=>{
              const last = [...messages].reverse().find(m=> m.role==='assistant')
              const ev = last? extractEvFilter(last.content) : null
              return (
                <button
                  onClick={()=> { if (ev) onApplyFilter(ev) }}
                  disabled={!ev}
                  title={ev? `Apply: ${ev}` : 'No EV filter detected in reply'}
                  style={{ padding:'9px 12px', background: ev? '#16a34a' : '#9ca3af', color:'#fff', border:'none', borderRadius:8, cursor: ev? 'pointer':'not-allowed' }}
                >Apply</button>
              )
            })()}
          </div>
        </div>
      )}
    </>
  )
}
