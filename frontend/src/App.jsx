import { useState, useRef, useCallback } from 'react'

// ─── API Configuration ──────────────────────────────────────────────────────
// VITE_API_BASE is set in .env.local for dev (http://127.0.0.1:8000)
// and in Vercel Environment Variables for production.
// Falls back to the same origin so the Vite proxy works without the env var.
const API_BASE = import.meta.env.VITE_API_BASE || ''
const UPLOAD_ENDPOINT = `${API_BASE}/upload-apk`

// ─── Helpers ─────────────────────────────────────────────────────────────────
function formatBytes(bytes) {
  if (!bytes || bytes === 0) return '0 B'
  const k = 1024
  const sizes = ['B', 'KB', 'MB', 'GB']
  const i = Math.floor(Math.log(bytes) / Math.log(k))
  return `${parseFloat((bytes / Math.pow(k, i)).toFixed(1))} ${sizes[i]}`
}

// Normalise classification to a CSS class name
function classKey(classification) {
  if (!classification) return 'unavailable'
  return classification.toLowerCase()
}

// ─── Primitive components ─────────────────────────────────────────────────────

function KV({ label, value }) {
  const empty = value === null || value === undefined || value === ''
  return (
    <>
      <span className="kv-key">{label}</span>
      {empty
        ? <span className="kv-null">Not available</span>
        : <span className="kv-val">{String(value)}</span>
      }
    </>
  )
}

function TagList({ items, emptyMsg = 'None' }) {
  if (!items || items.length === 0) {
    return <span className="tag-empty">{emptyMsg}</span>
  }
  return (
    <div className="tag-list">
      {items.map((item, i) => <span key={i} className="tag">{item}</span>)}
    </div>
  )
}

function Card({ icon, title, count, children }) {
  return (
    <div className="card">
      <div className="card-header">
        <span className="ch-icon">{icon}</span>
        {title}
        {count !== undefined && <span className="ch-count">{count}</span>}
      </div>
      <div className="card-body">
        {children}
      </div>
    </div>
  )
}

// ─── Collapsible component group ──────────────────────────────────────────────
function ComponentGroup({ label, items }) {
  const [open, setOpen] = useState(true)
  return (
    <div className="comp-group">
      <div className="comp-group-header" onClick={() => setOpen(o => !o)}>
        {label}
        <span className="cg-count">{items?.length ?? 0}</span>
        <span className="cg-toggle">{open ? '▲' : '▼'}</span>
      </div>
      {open && <TagList items={items} emptyMsg="None declared" />}
    </div>
  )
}

// ─── Risk Score Hero ──────────────────────────────────────────────────────────
function RiskHero({ risk, filename }) {
  const score          = risk?.score          // null if analysis failed
  const classification = risk?.classification  // null if analysis failed
  const findings       = risk?.findings       ?? []
  const summary        = risk?.summary        ?? ''

  const ck = classKey(classification)
  const isUnavailable = score === null || score === undefined

  const critCount = findings.filter(f => f.severity === 'critical').length
  const highCount  = findings.filter(f => f.severity === 'high').length

  return (
    <div className="risk-hero">
      {/* Dial */}
      <div className="risk-dial">
        <div className={`risk-score-circle ${ck}`}>
          {isUnavailable
            ? <span className={`risk-score-num ${ck}`}>N/A</span>
            : <>
                <span className={`risk-score-num ${ck}`}>{score}</span>
                <span className="risk-score-denom">/ 100</span>
              </>
          }
        </div>
        <span className={`risk-classification-badge ${ck}`}>
          {classification ?? 'Unavailable'}
        </span>
      </div>

      {/* Meta */}
      <div className="risk-meta">
        <div className="risk-meta-header">
          <h3>Risk Assessment</h3>
        </div>

        {/* Stats row */}
        <div className="risk-stat-row">
          <div className="risk-stat">
            <span className="stat-label">Findings</span>
            <span className="stat-value">{findings.length}</span>
          </div>
          {critCount > 0 && (
            <div className="risk-stat">
              <span className="stat-label" style={{ color: 'var(--sev-critical)' }}>Critical</span>
              <span className="stat-value" style={{ color: 'var(--sev-critical)' }}>{critCount}</span>
            </div>
          )}
          {highCount > 0 && (
            <div className="risk-stat">
              <span className="stat-label" style={{ color: 'var(--sev-high)' }}>High</span>
              <span className="stat-value" style={{ color: 'var(--sev-high)' }}>{highCount}</span>
            </div>
          )}
          <div className="risk-stat">
            <span className="stat-label">File</span>
            <span className="stat-value" style={{ fontWeight: 500, fontSize: 12 }}>
              {filename || '—'}
            </span>
          </div>
        </div>

        {/* Summary — directly from backend, never rewritten */}
        {summary && (
          <div className="risk-summary-text">
            {summary}
          </div>
        )}
      </div>
    </div>
  )
}

// ─── Findings List ────────────────────────────────────────────────────────────
function FindingsPanel({ findings }) {
  if (!findings || findings.length === 0) {
    return (
      <Card icon="🔍" title="Risk Findings" count={0}>
        <span className="tag-empty">No risk signals triggered.</span>
      </Card>
    )
  }

  // Sort: critical first, then by points desc
  const sorted = [...findings].sort((a, b) => {
    const order = { critical: 0, high: 1, medium: 2, low: 3 }
    const sa = order[a.severity] ?? 4
    const sb = order[b.severity] ?? 4
    if (sa !== sb) return sa - sb
    return b.points - a.points
  })

  return (
    <Card icon="🔍" title="Risk Findings" count={findings.length}>
      <div className="findings-list">
        {sorted.map((f, i) => (
          <div key={i} className={`finding-item ${f.severity || 'low'}`}>
            <div className="finding-top">
              <span className="finding-rule-id">{f.rule_id}</span>
              <span className={`sev-badge ${f.severity || 'low'}`}>{f.severity}</span>
              <span className="finding-category">{f.category}</span>
              <span className="finding-points">+{f.points} pts</span>
            </div>
            <div className="finding-reason">{f.reason}</div>
          </div>
        ))}
      </div>
    </Card>
  )
}

// ─── Permissions Panel ────────────────────────────────────────────────────────
function PermissionsPanel({ permissions }) {
  const [query, setQuery] = useState('')
  const list = permissions ?? []
  const filtered = query.trim()
    ? list.filter(p => p.toLowerCase().includes(query.toLowerCase()))
    : list

  return (
    <Card icon="🔐" title="Permissions" count={list.length}>
      {list.length > 5 && (
        <input
          className="perm-search"
          type="text"
          placeholder="Filter permissions…"
          value={query}
          onChange={e => setQuery(e.target.value)}
        />
      )}
      {filtered.length === 0 && query
        ? <span className="tag-empty">No permissions match "{query}"</span>
        : <TagList items={filtered} emptyMsg="No permissions declared" />
      }
    </Card>
  )
}

// ─── Components Panel ─────────────────────────────────────────────────────────
function ComponentsPanel({ components }) {
  const c = components ?? {}
  return (
    <Card icon="🧩" title="App Components">
      <ComponentGroup label="Activities"         items={c.activities} />
      <ComponentGroup label="Services"           items={c.services} />
      <ComponentGroup label="Broadcast Receivers" items={c.receivers} />
      <ComponentGroup label="Content Providers"  items={c.providers} />
    </Card>
  )
}

// ─── APK Details Panel ────────────────────────────────────────────────────────
function ApkDetailsPanel({ data }) {
  const isSuccess = data.analysis_status === 'success'
  return (
    <Card icon="📱" title="APK Details">
      <div className="kv-grid">
        <KV label="Filename"      value={data.filename} />
        <KV label="File Size"     value={formatBytes(data.size_bytes)} />
        <span className="kv-key">Analysis</span>
        <span className="kv-val">
          <span className={`status-badge ${isSuccess ? 'success' : 'failed'}`}>
            {isSuccess ? '✓ Success' : '✕ Failed'}
          </span>
        </span>
        <KV label="Package Name"  value={data.app?.package_name} />
        <KV label="App Label"     value={data.app?.label} />
        <KV label="Version"       value={data.app?.version} />
        <KV label="DEX Files"     value={data.dex?.count ?? 0} />
      </div>
    </Card>
  )
}

// ─── Certificate Panel ────────────────────────────────────────────────────────
function CertificatePanel({ certificate }) {
  const hasCert = certificate && Object.keys(certificate).length > 0
  return (
    <Card icon="🔏" title="Certificate">
      {hasCert
        ? (
          <div className="kv-grid">
            <KV label="Subject"       value={certificate.subject} />
            <KV label="Issuer"        value={certificate.issuer} />
            <KV label="Serial Number" value={certificate.serial_number} />
          </div>
        )
        : <p className="cert-unavailable">Certificate information unavailable.</p>
      }
    </Card>
  )
}

// ─── API Indicators Panel ─────────────────────────────────────────────────────
function ApiIndicatorsPanel({ apis }) {
  const list = apis ?? []
  const SHOW = 80
  return (
    <Card icon="⚙️" title="Method / API References" count={list.length}>
      {list.length === 0
        ? <span className="tag-empty">No method references extracted.</span>
        : (
          <>
            <TagList items={list.slice(0, SHOW)} />
            {list.length > SHOW && (
              <p className="api-note">
                Showing {SHOW} of {list.length} extracted references. Full list available in raw JSON.
              </p>
            )}
          </>
        )
      }
    </Card>
  )
}

// ─── Analysis Errors Panel ────────────────────────────────────────────────────
function AnalysisErrorsPanel({ errors }) {
  if (!errors || errors.length === 0) return null
  return (
    <Card icon="⚠️" title="Analysis Errors">
      <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
        {errors.map((e, i) => (
          <div key={i} className="failed-error-item">{e}</div>
        ))}
      </div>
    </Card>
  )
}

// ─── Analysis Failed State ────────────────────────────────────────────────────
function AnalysisFailedBanner({ data }) {
  return (
    <div className="analysis-failed-banner">
      <h3>Analysis failed — risk assessment unavailable.</h3>
      <p>
        The uploaded file could not be parsed as a valid Android APK.
        Static analysis requires a well-formed APK file.
        This is not a risk assessment — no score was generated.
      </p>
      {data.errors && data.errors.length > 0 && (
        <div className="failed-errors">
          {data.errors.map((e, i) => (
            <div key={i} className="failed-error-item">{e}</div>
          ))}
        </div>
      )}
    </div>
  )
}

// ─── Full Results View ────────────────────────────────────────────────────────
function AnalysisResults({ data }) {
  const failed = data.analysis_status !== 'success'

  return (
    <div className="results-layout">

      {/* ── Failed banner — shown instead of risk score if analysis failed ── */}
      {failed && <AnalysisFailedBanner data={data} />}

      {/* ── Risk Score Hero — only shown on success with real risk data ── */}
      {!failed && (
        <RiskHero risk={data.risk} filename={data.filename} />
      )}

      {/* ── Findings (full width — most important section) ── */}
      {!failed && (
        <FindingsPanel findings={data.risk?.findings} />
      )}

      {/* ── Two-column grid for detail panels ── */}
      <div className="panel-grid-2">
        <ApkDetailsPanel data={data} />
        <CertificatePanel certificate={data.certificate} />
        <PermissionsPanel permissions={data.permissions} />
        <ComponentsPanel components={data.components} />
      </div>

      {/* ── API indicators (full width — can be long) ── */}
      <ApiIndicatorsPanel apis={data.apis} />

      {/* ── Errors (always shown if present, even on success) ── */}
      <AnalysisErrorsPanel errors={data.errors} />

    </div>
  )
}

// ─── Upload Zone ──────────────────────────────────────────────────────────────
function UploadZone({ onResult }) {
  const [file, setFile]         = useState(null)
  const [loading, setLoading]   = useState(false)
  const [error, setError]       = useState(null)
  const [dragging, setDragging] = useState(false)
  const inputRef = useRef(null)

  function selectFile(f) {
    if (!f) return
    if (!f.name.toLowerCase().endsWith('.apk')) {
      setError('Only .apk files are accepted.')
      return
    }
    setError(null)
    setFile(f)
  }

  function handleInputChange(e) { selectFile(e.target.files?.[0] ?? null) }

  function handleClear() {
    setFile(null)
    setError(null)
    onResult(null)
    if (inputRef.current) inputRef.current.value = ''
  }

  const handleDragOver  = useCallback((e) => { e.preventDefault(); setDragging(true) }, [])
  const handleDragLeave = useCallback(() => setDragging(false), [])
  const handleDrop      = useCallback((e) => {
    e.preventDefault(); setDragging(false)
    selectFile(e.dataTransfer.files?.[0] ?? null)
  }, [])

  async function handleAnalyze() {
    if (!file) { setError('Please select an APK file first.'); return }

    setLoading(true)
    setError(null)
    onResult(null)

    const formData = new FormData()
    formData.append('file', file)  // must match FastAPI param name: `file`

    try {
      const response = await fetch(UPLOAD_ENDPOINT, { method: 'POST', body: formData })

      if (!response.ok) {
        let detail = `Server responded with HTTP ${response.status}`
        try { const b = await response.json(); if (b.detail) detail = b.detail } catch (_) {}
        throw new Error(detail)
      }

      const data = await response.json()
      if (typeof data !== 'object' || !('analysis_status' in data)) {
        throw new Error('Unexpected response format from backend.')
      }
      onResult(data)

    } catch (err) {
      const msg = (err.name === 'TypeError' && err.message.includes('fetch'))
        ? 'Cannot reach the backend. Make sure the FastAPI server is running.'
        : (err.message || 'An unknown error occurred.')
      setError(msg)
    } finally {
      setLoading(false)
    }
  }

  return (
    <>
      <div className="upload-card">
        <h2>Upload APK for Static Analysis</h2>

        <div
          className={`drop-zone${dragging ? ' active' : ''}`}
          onDragOver={handleDragOver}
          onDragLeave={handleDragLeave}
          onDrop={handleDrop}
        >
          <input
            ref={inputRef}
            type="file"
            accept=".apk,application/vnd.android.package-archive"
            onChange={handleInputChange}
            disabled={loading}
          />
          <div className="drop-icon">📂</div>
          <p className="drop-label">
            Drag &amp; drop an APK here, or <span>browse to select</span>
          </p>
          <p className="drop-hint">Only .apk files • No file is executed or installed</p>
        </div>

        {file && (
          <div className="selected-file">
            <span className="file-icon">📦</span>
            <div>
              <div className="file-name">{file.name}</div>
              <div className="file-size">{formatBytes(file.size)}</div>
            </div>
            <button className="clear-btn" onClick={handleClear} title="Remove">×</button>
          </div>
        )}

        <button
          className="analyze-btn"
          onClick={handleAnalyze}
          disabled={!file || loading}
        >
          {loading ? 'Running static analysis…' : 'Analyze APK'}
        </button>
      </div>

      {loading && (
        <div className="status-bar loading">
          <div className="spinner" />
          Uploading and performing static analysis — this may take a moment…
        </div>
      )}

      {error && (
        <div className="status-bar error">
          <span>⚠</span> {error}
        </div>
      )}
    </>
  )
}

// ─── App Root ─────────────────────────────────────────────────────────────────
export default function App() {
  const [result, setResult] = useState(null)

  return (
    <div className="app">
      <header>
        <div className="header-logo">
          <div className="logo-icon">🛡</div>
          <div className="logo-text">
            <h1>FraudGuard AI</h1>
            <p>Android APK Static Analysis</p>
          </div>
        </div>
        <span className="header-badge">SIH Prototype</span>
      </header>

      <main>
        <UploadZone onResult={setResult} />
        {result && <AnalysisResults data={result} />}
      </main>
    </div>
  )
}
