import { useState } from 'react'
import {
  apiNormalize,
  apiNormalizedIncidents,
  apiNormalizedExplain,
} from './api'

const SAMPLE_LOG = `{"timestamp":"2026-05-16T10:00:00Z","message":"login failed","severity":"warn","user":"alice","src_ip":"10.0.0.1","event_category":"auth","event_action":"login_failed","service":"auth-api"}
{"timestamp":"2026-05-16T10:03:00Z","message":"login failed","severity":"warn","user":"alice","src_ip":"10.0.0.1","event_category":"auth","event_action":"login_failed","service":"auth-api"}
{"timestamp":"2026-05-16T10:20:00Z","message":"login ok","severity":"info","user":"alice","src_ip":"10.0.0.1","event_category":"auth","event_action":"login_success","service":"auth-api"}
`

const SOURCE_TYPES = ['generic', 'ssh', 'apache']
const INPUT_FORMATS = ['jsonl', 'syslog']

function App() {
  const [content, setContent] = useState(SAMPLE_LOG)
  const [sourceType, setSourceType] = useState('generic')
  const [inputFormat, setInputFormat] = useState('jsonl')
  const [windowMinutes, setWindowMinutes] = useState(15)
  const [top, setTop] = useState(5)
  const [useAi, setUseAi] = useState(false)

  const [normalizeResult, setNormalizeResult] = useState(null)
  const [incidentsResult, setIncidentsResult] = useState(null)
  const [selectedIncidentIndex, setSelectedIncidentIndex] = useState(null)
  const [explainResult, setExplainResult] = useState(null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState(null)

  const hasIncidents =
    incidentsResult && Array.isArray(incidentsResult.incidents)

  async function handleNormalize() {
    setLoading(true)
    setError(null)
    setExplainResult(null)
    setIncidentsResult(null)
    setSelectedIncidentIndex(null)

    try {
      const payload = {
        content,
        source_type: sourceType,
        input_format: inputFormat,
        mapping: null,
        window_minutes: windowMinutes,
        top,
      }
      const data = await apiNormalize(payload)
      setNormalizeResult(data)
    } catch (e) {
      setError(e.message)
    } finally {
      setLoading(false)
    }
  }

  async function handleGroupIncidents() {
    setLoading(true)
    setError(null)
    setExplainResult(null)
    setSelectedIncidentIndex(null)

    try {
      const payload = {
        content,
        source_type: sourceType,
        input_format: inputFormat,
        mapping: null,
        window_minutes: windowMinutes,
        top,
      }
      const data = await apiNormalizedIncidents(payload)
      setIncidentsResult(data)
    } catch (e) {
      setError(e.message)
    } finally {
      setLoading(false)
    }
  }

  async function handleExplain(index) {
    if (!hasIncidents) return
    setLoading(true)
    setError(null)

    try {
      const payload = {
        content,
        source_type: sourceType,
        input_format: inputFormat,
        mapping: null,
        window_minutes: windowMinutes,
        top,
        index,
        first: false,
        use_ai: useAi,
      }
      const data = await apiNormalizedExplain(payload)
      setExplainResult(data)
      setSelectedIncidentIndex(index)
    } catch (e) {
      setError(e.message)
    } finally {
      setLoading(false)
    }
  }

  return (
    <div
      style={{
        fontFamily: 'system-ui, sans-serif',
        padding: '1.5rem',
        maxWidth: '1200px',
        margin: '0 auto',
      }}
    >
      <h1 style={{ marginBottom: '0.5rem' }}>AegisLog UI</h1>
      <p style={{ marginBottom: '1.5rem', color: '#555' }}>
        Paste logs, normalize them, group incidents, and inspect explain results with optional AI analysis.
      </p>

      <section
        style={{
          display: 'grid',
          gridTemplateColumns: '1.5fr 1fr',
          gap: '1.5rem',
          marginBottom: '1.5rem',
        }}
      >
        <div>
          <label style={{ display: 'block', fontWeight: 600, marginBottom: '0.5rem' }}>
            Log content
          </label>
          <textarea
            value={content}
            onChange={e => setContent(e.target.value)}
            rows={12}
            style={{
              width: '100%',
              fontFamily: 'monospace',
              fontSize: '0.9rem',
              borderRadius: '4px',
              border: '1px solid #ccc',
              padding: '0.5rem',
              resize: 'vertical',
            }}
          />
        </div>

        <div>
          <div style={{ marginBottom: '0.75rem' }}>
            <label style={{ display: 'block', fontWeight: 600, marginBottom: '0.25rem' }}>
              Source type
            </label>
            <select
              value={sourceType}
              onChange={e => setSourceType(e.target.value)}
              style={{ width: '100%', padding: '0.35rem', borderRadius: '4px' }}
            >
              {SOURCE_TYPES.map(st => (
                <option key={st} value={st}>
                  {st}
                </option>
              ))}
            </select>
          </div>

          <div style={{ marginBottom: '0.75rem' }}>
            <label style={{ display: 'block', fontWeight: 600, marginBottom: '0.25rem' }}>
              Input format
            </label>
            <select
              value={inputFormat}
              onChange={e => setInputFormat(e.target.value)}
              style={{ width: '100%', padding: '0.35rem', borderRadius: '4px' }}
            >
              {INPUT_FORMATS.map(fmt => (
                <option key={fmt} value={fmt}>
                  {fmt}
                </option>
              ))}
            </select>
          </div>

          <div style={{ display: 'flex', gap: '0.75rem', marginBottom: '0.75rem' }}>
            <div style={{ flex: 1 }}>
              <label style={{ display: 'block', fontWeight: 600, marginBottom: '0.25rem' }}>
                Window minutes
              </label>
              <input
                type="number"
                min={1}
                max={1440}
                value={windowMinutes}
                onChange={e => setWindowMinutes(Number(e.target.value))}
                style={{ width: '100%', padding: '0.35rem', borderRadius: '4px' }}
              />
            </div>
            <div style={{ flex: 1 }}>
              <label style={{ display: 'block', fontWeight: 600, marginBottom: '0.25rem' }}>
                Top
              </label>
              <input
                type="number"
                min={1}
                max={100}
                value={top}
                onChange={e => setTop(Number(e.target.value))}
                style={{ width: '100%', padding: '0.35rem', borderRadius: '4px' }}
              />
            </div>
          </div>

          <label
            style={{
              display: 'flex',
              alignItems: 'center',
              gap: '0.5rem',
              marginBottom: '1rem',
              fontWeight: 500,
            }}
          >
            <input
              type="checkbox"
              checked={useAi}
              onChange={e => setUseAi(e.currentTarget.checked)}
            />
            Use AI explanation
          </label>

          <div style={{ display: 'flex', gap: '0.75rem', marginTop: '0.5rem' }}>
            <button
              type="button"
              onClick={handleNormalize}
              disabled={loading}
              style={{
                flex: 1,
                padding: '0.5rem 0.75rem',
                borderRadius: '4px',
                border: '1px solid #0f766e',
                background: '#0d9488',
                color: '#fff',
                fontWeight: 600,
                cursor: 'pointer',
              }}
            >
              {loading ? 'Working…' : 'Normalize'}
            </button>
            <button
              type="button"
              onClick={handleGroupIncidents}
              disabled={loading}
              style={{
                flex: 1,
                padding: '0.5rem 0.75rem',
                borderRadius: '4px',
                border: '1px solid #1d4ed8',
                background: '#2563eb',
                color: '#fff',
                fontWeight: 600,
                cursor: 'pointer',
              }}
            >
              {loading ? 'Working…' : 'Group incidents'}
            </button>
          </div>

          {error && (
            <p style={{ color: '#b91c1c', marginTop: '0.75rem', whiteSpace: 'pre-wrap' }}>
              {error}
            </p>
          )}
        </div>
      </section>

      <section style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '1.5rem' }}>
        <div>
          <h2 style={{ marginBottom: '0.5rem' }}>Normalization summary</h2>
          {normalizeResult ? (
            <pre
              style={{
                background: '#f9fafb',
                borderRadius: '4px',
                padding: '0.75rem',
                fontSize: '0.85rem',
                maxHeight: '300px',
                overflow: 'auto',
              }}
            >
              {JSON.stringify(normalizeResult.summary, null, 2)}
            </pre>
          ) : (
            <p style={{ color: '#6b7280' }}>Run “Normalize” to see summary and preview.</p>
          )}
        </div>

        <div>
          <h2 style={{ marginBottom: '0.5rem' }}>Incidents</h2>
          {hasIncidents ? (
            <div
              style={{
                border: '1px solid #e5e7eb',
                borderRadius: '4px',
                maxHeight: '300px',
                overflow: 'auto',
              }}
            >
              {incidentsResult.incidents.map((inc, idx) => (
                <div
                  key={inc.incident_id}
                  style={{
                    padding: '0.5rem 0.75rem',
                    borderBottom: '1px solid #e5e7eb',
                    background:
                      idx === selectedIncidentIndex ? 'rgba(37, 99, 235, 0.08)' : 'transparent',
                    cursor: 'pointer',
                  }}
                  onClick={() => handleExplain(idx)}
                >
                  <div style={{ fontWeight: 600, marginBottom: '0.25rem' }}>
                    [{idx}] {inc.summary?.title ?? inc.incident_id}
                  </div>
                  <div style={{ fontSize: '0.8rem', color: '#4b5563' }}>
                    severity={inc.severity} · priority={inc.priority} · events={inc.event_count}
                  </div>
                </div>
              ))}
            </div>
          ) : (
            <p style={{ color: '#6b7280' }}>Run “Group incidents” to see incident clusters.</p>
          )}
        </div>
      </section>

      <section style={{ marginTop: '1.5rem' }}>
        <h2 style={{ marginBottom: '0.5rem' }}>Explain result</h2>
        {explainResult ? (
          <>
            <div
              style={{
                display: 'grid',
                gridTemplateColumns: '1fr 1fr',
                gap: '1.5rem',
                marginBottom: '1.5rem',
              }}
            >
              <div>
                <h3 style={{ fontSize: '1rem', marginBottom: '0.25rem' }}>Incident</h3>
                <pre
                  style={{
                    background: '#f9fafb',
                    borderRadius: '4px',
                    padding: '0.75rem',
                    fontSize: '0.85rem',
                    maxHeight: '260px',
                    overflow: 'auto',
                  }}
                >
                  {JSON.stringify(explainResult.incident, null, 2)}
                </pre>
              </div>
              <div>
                <h3 style={{ fontSize: '1rem', marginBottom: '0.25rem' }}>Evidence</h3>
                <pre
                  style={{
                    background: '#f9fafb',
                    borderRadius: '4px',
                    padding: '0.75rem',
                    fontSize: '0.85rem',
                    maxHeight: '260px',
                    overflow: 'auto',
                  }}
                >
                  {JSON.stringify(explainResult.incident_evidence, null, 2)}
                </pre>
              </div>
            </div>

            <div>
              <h3 style={{ fontSize: '1rem', marginBottom: '0.25rem' }}>AI analysis</h3>
              {explainResult.ai_analysis ? (
                <pre
                  style={{
                    background: '#ecfeff',
                    border: '1px solid #a5f3fc',
                    borderRadius: '4px',
                    padding: '0.75rem',
                    fontSize: '0.85rem',
                    overflow: 'auto',
                  }}
                >
                  {JSON.stringify(explainResult.ai_analysis, null, 2)}
                </pre>
              ) : explainResult.ai_error ? (
                <div
                  style={{
                    background: '#fef2f2',
                    border: '1px solid #fecaca',
                    color: '#991b1b',
                    borderRadius: '4px',
                    padding: '0.75rem',
                    whiteSpace: 'pre-wrap',
                  }}
                >
                  {explainResult.ai_error}
                </div>
              ) : (
                <p style={{ color: '#6b7280' }}>
                  No AI analysis returned. Turn on “Use AI explanation” and click an incident.
                </p>
              )}
            </div>
          </>
        ) : (
          <p style={{ color: '#6b7280' }}>
            Click an incident to fetch explain output{useAi ? ' with AI enabled' : ''}.
          </p>
        )}
      </section>
    </div>
  )
}

export default App