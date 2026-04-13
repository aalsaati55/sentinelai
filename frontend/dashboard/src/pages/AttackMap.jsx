import { useEffect, useState, useRef, useMemo } from 'react'
import { RefreshCw, Globe, AlertTriangle, Wifi } from 'lucide-react'
import { api } from '../api'
import { Panel } from '../components/Panel'
import { Badge } from '../components/Badge'

const SEV_COLOR = {
  critical: '#ef4444',
  high:     '#f97316',
  medium:   '#eab308',
  low:      '#22c55e',
}

const SEV_GLOW = {
  critical: '0 0 10px #ef4444aa',
  high:     '0 0 8px #f97316aa',
  medium:   '0 0 6px #eab30888',
  low:      '0 0 4px #22c55e66',
}

const W = 1010
const H = 505

// Convert lat/lon to x/y on an equirectangular projection
function latLonToXY(lat, lon, w = W, h = H) {
  const x = (lon + 180) * (w / 360)
  const y = (90 - lat) * (h / 180)
  return { x, y }
}

// Convert a GeoJSON ring (array of [lon,lat]) to an SVG path string
function ringToPath(ring) {
  return ring.map(([lon, lat], i) => {
    const { x, y } = latLonToXY(lat, lon)
    return `${i === 0 ? 'M' : 'L'}${x.toFixed(2)},${y.toFixed(2)}`
  }).join(' ') + ' Z'
}

// Build one combined SVG path string from a GeoJSON FeatureCollection
function geojsonToSvgPaths(geojson) {
  if (!geojson || !geojson.features) return []
  const paths = []
  for (const feature of geojson.features) {
    const { type, coordinates } = feature.geometry
    if (type === 'Polygon') {
      paths.push(coordinates.map(ringToPath).join(' '))
    } else if (type === 'MultiPolygon') {
      for (const poly of coordinates) {
        paths.push(poly.map(ringToPath).join(' '))
      }
    }
  }
  return paths
}

function Tooltip({ point, pos }) {
  if (!point) return null
  const color = SEV_COLOR[point.severity] || '#6366f1'
  return (
    <div
      className="pointer-events-none fixed z-50 bg-[#1c2128] border border-[#30363d] rounded-xl shadow-2xl p-3 w-56 text-sm"
      style={{ left: pos.x + 14, top: pos.y - 10 }}
    >
      <div className="flex items-center gap-2 mb-2">
        <span className="text-lg">{point.country_code ? countryFlag(point.country_code) : '🌐'}</span>
        <div>
          <div className="font-semibold text-white text-xs">{point.city || '—'}</div>
          <div className="text-slate-400 text-[11px]">{point.country || '—'}</div>
        </div>
      </div>
      <div className="space-y-1 text-[11px]">
        {point.from_ti && (
          <div className="flex items-center gap-1 mb-1.5 px-2 py-0.5 rounded-full bg-purple-500/10 border border-purple-500/20 w-fit">
            <span className="text-purple-400 font-semibold">⚠ Threat Intelligence</span>
          </div>
        )}
        <div className="flex justify-between">
          <span className="text-slate-500">IP</span>
          <code className="text-slate-300 font-mono">{point.ip}</code>
        </div>
        <div className="flex justify-between">
          <span className="text-slate-500">Alerts</span>
          <span className="text-white font-semibold">{point.alert_count || '—'}</span>
        </div>
        <div className="flex justify-between">
          <span className="text-slate-500">Severity</span>
          <span className="font-semibold" style={{ color }}>{point.severity?.toUpperCase()}</span>
        </div>
        {point.isp && (
          <div className="flex justify-between gap-2">
            <span className="text-slate-500">ISP</span>
            <span className="text-slate-400 text-right truncate max-w-[130px]">{point.isp}</span>
          </div>
        )}
      </div>
    </div>
  )
}

function countryFlag(code) {
  if (!code || code.length !== 2) return '🌐'
  if (code === '--') return '🏠'
  const offset = 0x1F1E6 - 65
  return String.fromCodePoint(code.toUpperCase().charCodeAt(0) + offset) +
         String.fromCodePoint(code.toUpperCase().charCodeAt(1) + offset)
}

export function AttackMap() {
  const [points, setPoints] = useState([])
  const [loading, setLoading] = useState(true)
  const [hovered, setHovered] = useState(null)
  const [mousePos, setMousePos] = useState({ x: 0, y: 0 })
  const [svgSize, setSvgSize] = useState({ w: 1010, h: 505 })
  const [worldPaths, setWorldPaths] = useState([])
  const [isZoomed, setIsZoomed] = useState(false)
  const containerRef = useRef(null)
  const svgRef = useRef(null)
  const groupRef = useRef(null)
  const dragRef = useRef(null)
  const xfRef = useRef({ scale: 1, tx: 0, ty: 0 })

  useEffect(() => {
    fetch('/world.geojson')
      .then(r => r.json())
      .then(gj => setWorldPaths(geojsonToSvgPaths(gj)))
      .catch(() => {})
  }, [])

  async function load() {
    setLoading(true)
    try {
      const res = await api.geoMap()
      setPoints(res.points || [])
    } catch (_) {
      setPoints([])
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => { load() }, [])

  // Track container size for responsive SVG scaling
  useEffect(() => {
    if (!containerRef.current) return
    const ro = new ResizeObserver(entries => {
      for (const e of entries) {
        const w = e.contentRect.width
        setSvgSize({ w, h: w * 0.5 })
      }
    })
    ro.observe(containerRef.current)
    return () => ro.disconnect()
  }, [])

  function applyTransform() {
    const { scale, tx, ty } = xfRef.current
    if (groupRef.current)
      groupRef.current.setAttribute('transform', `translate(${tx},${ty}) scale(${scale})`)
    setIsZoomed(scale > 1.01)
  }

  function resetZoom() {
    xfRef.current = { scale: 1, tx: 0, ty: 0 }
    applyTransform()
  }

  // Attach all gesture listeners once, manipulate DOM directly — zero React re-renders during gesture
  useEffect(() => {
    const svg = svgRef.current
    if (!svg) return

    function onWheel(e) {
      e.preventDefault()
      const rect = svg.getBoundingClientRect()
      const mx = (e.clientX - rect.left) * (1010 / rect.width)
      const my = (e.clientY - rect.top)  * (505  / rect.height)
      const factor = e.deltaY < 0 ? 1.15 : 1 / 1.15
      const t = xfRef.current
      const newScale = Math.min(12, Math.max(1, t.scale * factor))
      xfRef.current = {
        scale: newScale,
        tx: mx - (mx - t.tx) * (newScale / t.scale),
        ty: my - (my - t.ty) * (newScale / t.scale),
      }
      applyTransform()
    }

    function onMouseMove(e) {
      // Only update React state for tooltip when not dragging — avoids re-renders during drag
      if (!dragRef.current) setMousePos({ x: e.clientX, y: e.clientY })
      if (!dragRef.current) return
      const rect = svg.getBoundingClientRect()
      const scaleX = 1010 / rect.width
      const scaleY = 505  / rect.height
      xfRef.current = {
        ...xfRef.current,
        tx: dragRef.current.startTx + (e.clientX - dragRef.current.startX) * scaleX,
        ty: dragRef.current.startTy + (e.clientY - dragRef.current.startY) * scaleY,
      }
      applyTransform()
    }

    function onMouseUp() { dragRef.current = null }

    svg.addEventListener('wheel', onWheel, { passive: false })
    window.addEventListener('mousemove', onMouseMove)
    window.addEventListener('mouseup', onMouseUp)
    return () => {
      svg.removeEventListener('wheel', onWheel)
      window.removeEventListener('mousemove', onMouseMove)
      window.removeEventListener('mouseup', onMouseUp)
    }
  }, [])

  function handleMouseDown(e) {
    dragRef.current = {
      startX: e.clientX, startY: e.clientY,
      startTx: xfRef.current.tx, startTy: xfRef.current.ty,
    }
  }

  const criticalCount = points.filter(p => p.severity === 'critical').length
  const highCount     = points.filter(p => p.severity === 'high').length
  const countries     = new Set(points.map(p => p.country_code)).size

  return (
    <div className="space-y-5">
      <div>
        <h2 className="text-xl font-bold text-white mb-1">Attack Map</h2>
        <p className="text-sm text-slate-500">Live geographic view of alert source IPs resolved via GeoIP</p>
      </div>

      {/* Stats strip */}
      <div className="grid grid-cols-4 gap-4">
        {[
          { label: 'Total Sources', value: points.length, icon: <Globe size={16} className="text-blue-400" />, color: 'text-blue-400' },
          { label: 'Countries',     value: countries,     icon: <span className="text-base">🌍</span>,          color: 'text-purple-400' },
          { label: 'Critical IPs',  value: criticalCount, icon: <AlertTriangle size={16} className="text-red-400" />, color: 'text-red-400' },
          { label: 'High IPs',      value: highCount,     icon: <Wifi size={16} className="text-orange-400" />, color: 'text-orange-400' },
        ].map(({ label, value, icon, color }) => (
          <Panel key={label} className="flex items-center gap-3 py-3">
            <div className="p-2 bg-white/5 rounded-lg">{icon}</div>
            <div>
              <div className={`text-2xl font-bold ${color}`}>{value}</div>
              <div className="text-xs text-slate-500">{label}</div>
            </div>
          </Panel>
        ))}
      </div>

      <Panel>
        {/* Toolbar */}
        <div className="flex items-center gap-3 mb-4 flex-wrap">
          <button
            onClick={load}
            className="flex items-center gap-2 bg-[#1c2128] border border-[#30363d] hover:border-blue-500 text-slate-300 text-sm px-3 py-2 rounded-lg transition-colors"
          >
            <RefreshCw size={13} className={loading ? 'animate-spin' : ''} />
            Refresh
          </button>
          {isZoomed && (
            <button
              onClick={resetZoom}
              className="flex items-center gap-2 bg-[#1c2128] border border-[#30363d] hover:border-red-500 text-slate-400 text-sm px-3 py-2 rounded-lg transition-colors"
            >
              Reset Zoom
            </button>
          )}
          {/* Legend */}
          <div className="flex items-center gap-4 ml-auto text-xs text-slate-500">
            {Object.entries(SEV_COLOR).map(([sev, color]) => (
              <div key={sev} className="flex items-center gap-1.5">
                <div className="w-2.5 h-2.5 rounded-full" style={{ background: color }} />
                <span className="capitalize">{sev}</span>
              </div>
            ))}
            <div className="flex items-center gap-1.5">
              <div className="w-2.5 h-2.5 rounded-full" style={{ background: '#a855f7' }} />
              <span>Threat Intel</span>
            </div>
          </div>
        </div>

        {/* Map container */}
        <div
          ref={containerRef}
          className="relative w-full rounded-xl overflow-hidden bg-[#0d1117] border border-[#30363d]"
          style={{ minHeight: 320 }}
          onMouseDown={handleMouseDown}
        >
          {/* Zoom hint */}
          {!isZoomed && (
            <div className="absolute bottom-2 right-3 text-[10px] text-slate-600 pointer-events-none z-10 select-none">
              Scroll to zoom · Drag to pan
            </div>
          )}
          {/* World map SVG background */}
          <svg
            ref={svgRef}
            viewBox="0 0 1010 505"
            className="w-full"
            style={{ display: 'block', cursor: dragRef.current ? 'grabbing' : 'grab' }}
          >
            {/* Ocean background */}
            <rect width="1010" height="505" fill="#0d1117" />

            {/* Zoomable/pannable group — transform applied via DOM ref, not React state */}
            <g ref={groupRef}>

            {/* Local GeoJSON world landmasses rendered as SVG paths */}
            {worldPaths.map((d, i) => (
              <path key={i} d={d} fill="#1e2d3d" stroke="#2d4a6b" strokeWidth="0.4" opacity="0.9" />
            ))}

            {/* Grid lines */}
            {[-60, -30, 0, 30, 60].map(lat => {
              const { y } = latLonToXY(lat, 0)
              return <line key={lat} x1="0" y1={y} x2="1010" y2={y} stroke="#30363d" strokeWidth="0.5" />
            })}
            {[-120, -60, 0, 60, 120].map(lon => {
              const { x } = latLonToXY(0, lon)
              return <line key={lon} x1={x} y1="0" x2={x} y2="505" stroke="#30363d" strokeWidth="0.5" />
            })}

            {/* Equator highlight */}
            <line x1="0" y1="252.5" x2="1010" y2="252.5" stroke="#21262d" strokeWidth="1" />

            {/* Attack dots */}
            {points.map((point, i) => {
              const { x, y } = latLonToXY(point.lat, point.lon)
              const color = point.from_ti ? '#a855f7' : (SEV_COLOR[point.severity] || '#6366f1')
              const r = point.severity === 'critical' ? 6 :
                        point.severity === 'high'     ? 5 :
                        point.severity === 'medium'   ? 4 : 3
              const isHovered = hovered === i
              return (
                <g key={i}>
                  {/* Pulse ring for critical/high/TI */}
                  {(point.severity === 'critical' || point.severity === 'high' || point.from_ti) && (
                    <circle
                      cx={x} cy={y}
                      r={isHovered ? r + 8 : r + 5}
                      fill="none"
                      stroke={color}
                      strokeWidth="1"
                      opacity={isHovered ? 0.6 : 0.3}
                    />
                  )}
                  <circle
                    cx={x} cy={y}
                    r={isHovered ? r + 2 : r}
                    fill={color}
                    opacity={isHovered ? 1 : 0.85}
                    style={{ cursor: 'pointer', filter: isHovered ? `drop-shadow(0 0 8px ${color}aa)` : undefined }}
                    onMouseEnter={() => setHovered(i)}
                    onMouseLeave={() => setHovered(null)}
                  />
                </g>
              )
            })}

            {loading && (
              <text x="505" y="252" textAnchor="middle" fill="#6b7280" fontSize="14">
                Loading geographic data…
              </text>
            )}
            {!loading && points.length === 0 && (
              <text x="505" y="252" textAnchor="middle" fill="#6b7280" fontSize="14">
                No external IPs resolved yet — trigger some alerts first
              </text>
            )}
            </g>
          </svg>
        </div>

        {/* IP table below the map */}
        {points.length > 0 && (
          <div className="mt-5">
            <h3 className="text-xs font-semibold text-slate-500 uppercase tracking-wider mb-3">
              Resolved Attackers ({points.length})
            </h3>
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead>
                  <tr className="text-left">
                    {['Flag', 'IP', 'Country', 'City', 'ISP', 'Alerts', 'Severity', 'Source'].map(h => (
                      <th key={h} className="pb-2 pr-4 text-xs font-semibold uppercase tracking-wider text-slate-500 whitespace-nowrap">{h}</th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {[...points]
                    .sort((a, b) => {
                      const o = { critical: 4, high: 3, medium: 2, low: 1 }
                      return (o[b.severity] || 0) - (o[a.severity] || 0)
                    })
                    .map((p, i) => (
                      <tr
                        key={i}
                        className="border-t border-[#30363d] hover:bg-white/[0.02] transition-colors cursor-default"
                        onMouseEnter={() => {
                          const idx = points.indexOf(p)
                          setHovered(idx)
                        }}
                        onMouseLeave={() => setHovered(null)}
                      >
                        <td className="py-2.5 pr-4 text-lg">{countryFlag(p.country_code)}</td>
                        <td className="py-2.5 pr-4"><code className="text-xs font-mono text-slate-300">{p.ip}</code></td>
                        <td className="py-2.5 pr-4 text-slate-300 text-xs">{p.country || '—'}</td>
                        <td className="py-2.5 pr-4 text-slate-400 text-xs">{p.city || '—'}</td>
                        <td className="py-2.5 pr-4 text-slate-500 text-xs max-w-[180px] truncate">{p.isp || '—'}</td>
                        <td className="py-2.5 pr-4">
                          <span className="text-xs font-semibold text-white bg-white/10 px-2 py-0.5 rounded-full">{p.alert_count || '—'}</span>
                        </td>
                        <td className="py-2.5 pr-4"><Badge value={p.severity} /></td>
                        <td className="py-2.5">
                          {p.from_ti
                            ? <span className="text-[10px] px-1.5 py-0.5 rounded-full bg-purple-500/10 border border-purple-500/20 text-purple-400 font-semibold">Threat Intel</span>
                            : <span className="text-[10px] text-slate-600">Alerts</span>
                          }
                        </td>
                      </tr>
                    ))}
                </tbody>
              </table>
            </div>
          </div>
        )}
      </Panel>

      {/* Tooltip */}
      <Tooltip point={hovered !== null ? points[hovered] : null} pos={mousePos} />
    </div>
  )
}
