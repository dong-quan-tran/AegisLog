import { useMemo, useState } from "react";
import "./App.css";

const API_BASE = "http://127.0.0.1:8000";

const sampleLogs = `{"timestamp":"2026-05-11T21:00:00Z","level":"info","message":"User login succeeded","event_type":"auth","action":"login_success","username":"alice","client_ip":"192.168.1.10","hostname":"web-01","app":"auth-service","request_id":"req-1001"}
{"timestamp":"2026-05-11T21:01:05Z","level":"warn","message":"Repeated login failure","event_type":"auth","action":"login_failed","username":"bob","client_ip":"203.0.113.55","hostname":"web-01","app":"auth-service","request_id":"req-1002"}
{"timestamp":"2026-05-11T21:02:10Z","level":"error","message":"Upstream timeout","event_type":"app","action":"request_error","hostname":"api-01","app":"payments","status_code":504,"trace_id":"trace-7788"}
{"timestamp":"2026-05-11T21:03:15Z","level":"error","message":"Too many requests","event_type":"web","action":"rate_limit","client_ip":"198.51.100.22","hostname":"edge-01","app":"gateway","status_code":429}`;

const severityRank = {
  critical: 4,
  high: 3,
  medium: 2,
  low: 1,
  info: 0,
  unknown: -1,
};

const priorityRank = {
  critical: 4,
  high: 3,
  medium: 2,
  low: 1,
};

function toneValue(value = "") {
  return value.toLowerCase().trim();
}

function formatDate(value) {
  if (!value) return "Unknown time";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return value;
  return date.toLocaleString();
}

function SeverityPill({ value }) {
  const tone = toneValue(value) || "default";
  return <span className={`pill pill-${tone}`}>{value || "unknown"}</span>;
}

function StatCard({ label, value, hint }) {
  return (
    <div className="stat-card">
      <span className="stat-label">{label}</span>
      <strong>{value}</strong>
      <span className="stat-hint">{hint}</span>
    </div>
  );
}

function App() {
  const [content, setContent] = useState(sampleLogs);
  const [sourceType, setSourceType] = useState("generic");
  const [inputFormat, setInputFormat] = useState("jsonl");
  const [windowMinutes, setWindowMinutes] = useState(15);

  const [severityFilter, setSeverityFilter] = useState("all");
  const [sortMode, setSortMode] = useState("priority_desc");

  const [loadingIncidents, setLoadingIncidents] = useState(false);
  const [loadingExplain, setLoadingExplain] = useState(false);
  const [error, setError] = useState("");
  const [incidentsResponse, setIncidentsResponse] = useState(null);
  const [selectedIncidentId, setSelectedIncidentId] = useState(null);
  const [explainResponse, setExplainResponse] = useState(null);

  const incidents = incidentsResponse?.incidents || [];

  const filteredIncidents = useMemo(() => {
    let items = [...incidents];

    if (severityFilter !== "all") {
      items = items.filter(
        (incident) => toneValue(incident.priority) === severityFilter
      );
    }

    items.sort((a, b) => {
      if (sortMode === "priority_desc") {
        const p = (priorityRank[toneValue(b.priority)] || 0) - (priorityRank[toneValue(a.priority)] || 0);
        if (p !== 0) return p;
        return new Date(b.first_seen || 0) - new Date(a.first_seen || 0);
      }

      if (sortMode === "newest") {
        return new Date(b.first_seen || 0) - new Date(a.first_seen || 0);
      }

      if (sortMode === "oldest") {
        return new Date(a.first_seen || 0) - new Date(b.first_seen || 0);
      }

      if (sortMode === "events_desc") {
        return (b.event_count || 0) - (a.event_count || 0);
      }

      return 0;
    });

    return items;
  }, [incidents, severityFilter, sortMode]);

  const selectedIncident = useMemo(() => {
    if (!selectedIncidentId) return null;
    return filteredIncidents.find((item) => item.incident_id === selectedIncidentId)
      || incidents.find((item) => item.incident_id === selectedIncidentId)
      || null;
  }, [filteredIncidents, incidents, selectedIncidentId]);

  const stats = useMemo(() => {
    const priorityCounts = incidents.reduce(
      (acc, incident) => {
        const key = toneValue(incident.priority) || "unknown";
        acc[key] = (acc[key] || 0) + 1;
        return acc;
      },
      { critical: 0, high: 0, medium: 0, low: 0, unknown: 0 }
    );

    return {
      totalEvents: incidentsResponse?.total_events ?? 0,
      totalIncidents: incidentsResponse?.total_incidents ?? 0,
      parseErrors: incidentsResponse?.parse_errors?.length ?? 0,
      priorityCounts,
    };
  }, [incidents, incidentsResponse]);

  async function handleGroupIncidents() {
    setLoadingIncidents(true);
    setError("");
    setExplainResponse(null);
    setSelectedIncidentId(null);

    try {
      const res = await fetch(`${API_BASE}/generic-incidents`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          content,
          source_type: sourceType,
          input_format: inputFormat,
          window_minutes: Number(windowMinutes),
          top: 25,
        }),
      });

      if (!res.ok) {
        const text = await res.text();
        throw new Error(`generic-incidents failed: ${res.status} ${text}`);
      }

      const data = await res.json();
      setIncidentsResponse(data);
    } catch (err) {
      setError(err.message || "Failed to group incidents.");
    } finally {
      setLoadingIncidents(false);
    }
  }

  async function handleExplain(index, incident) {
    setLoadingExplain(true);
    setError("");
    setSelectedIncidentId(incident.incident_id);

    try {
      const res = await fetch(`${API_BASE}/generic-explain`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          content,
          source_type: sourceType,
          input_format: inputFormat,
          window_minutes: Number(windowMinutes),
          index,
          first: false,
          use_ai: false,
        }),
      });

      if (!res.ok) {
        const text = await res.text();
        throw new Error(`generic-explain failed: ${res.status} ${text}`);
      }

      const data = await res.json();
      setExplainResponse(data);
    } catch (err) {
      setError(err.message || "Failed to explain incident.");
    } finally {
      setLoadingExplain(false);
    }
  }

  async function handleExportSelected() {
    if (!explainResponse) return;
    const blob = new Blob([JSON.stringify(explainResponse, null, 2)], {
      type: "application/json",
    });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = "aegislog-incident-detail.json";
    a.click();
    URL.revokeObjectURL(url);
  }

  return (
    <div className="app-shell">
      <header className="topbar">
        <div className="brand-block">
          <p className="eyebrow">AegisLog</p>
          <h1>Incident workbench</h1>
          <p className="subtle">
            Paste logs, group related events, and inspect structured evidence.
          </p>
        </div>

        <div className="topbar-actions">
          <button className="button secondary" onClick={() => setContent(sampleLogs)}>
            Load sample
          </button>
          <button
            className="button primary"
            onClick={handleGroupIncidents}
            disabled={loadingIncidents}
          >
            {loadingIncidents ? "Grouping..." : "Group incidents"}
          </button>
        </div>
      </header>

      <main className="workspace">
        <section className="panel left-rail">
          <div className="panel-header">
            <div>
              <h2>Log input</h2>
              <p className="panel-subtitle">Send raw content to the FastAPI backend.</p>
            </div>
            <span className="meta-chip">Backend connected</span>
          </div>

          <label className="field">
            <span>Log content</span>
            <textarea
              value={content}
              onChange={(e) => setContent(e.target.value)}
              placeholder="Paste JSONL or syslog text here..."
            />
          </label>

          <div className="controls-grid">
            <label className="field">
              <span>Source type</span>
              <select value={sourceType} onChange={(e) => setSourceType(e.target.value)}>
                <option value="generic">generic</option>
                <option value="ssh">ssh</option>
                <option value="apache">apache</option>
              </select>
            </label>

            <label className="field">
              <span>Input format</span>
              <select value={inputFormat} onChange={(e) => setInputFormat(e.target.value)}>
                <option value="jsonl">jsonl</option>
                <option value="syslog">syslog</option>
              </select>
            </label>

            <label className="field">
              <span>Window minutes</span>
              <input
                type="number"
                min="1"
                max="1440"
                value={windowMinutes}
                onChange={(e) => setWindowMinutes(e.target.value)}
              />
            </label>
          </div>

          {error ? <div className="error-box">{error}</div> : null}
        </section>

        <section className="main-column">
          <section className="stats-grid">
            <StatCard label="Events" value={stats.totalEvents} hint="Processed input events" />
            <StatCard label="Incidents" value={stats.totalIncidents} hint="Grouped incident buckets" />
            <StatCard label="Parse errors" value={stats.parseErrors} hint="Lines rejected during parsing" />
            <StatCard label="High / critical" value={stats.priorityCounts.high + stats.priorityCounts.critical} hint="Most urgent buckets" />
          </section>

          <section className="panel list-panel">
            <div className="panel-header stacked-mobile">
              <div>
                <h2>Incidents</h2>
                <p className="panel-subtitle">
                  Review grouped incidents by severity, time, or event count.
                </p>
              </div>

              <div className="toolbar">
                <div className="chip-row" role="group" aria-label="Severity filter">
                  {["all", "critical", "high", "medium", "low"].map((level) => (
                    <button
                      key={level}
                      className={`filter-chip ${severityFilter === level ? "active" : ""}`}
                      onClick={() => setSeverityFilter(level)}
                    >
                      {level}
                    </button>
                  ))}
                </div>

                <label className="sort-control">
                  <span>Sort</span>
                  <select value={sortMode} onChange={(e) => setSortMode(e.target.value)}>
                    <option value="priority_desc">Priority</option>
                    <option value="newest">Newest</option>
                    <option value="oldest">Oldest</option>
                    <option value="events_desc">Event count</option>
                  </select>
                </label>
              </div>
            </div>

            <div className="list-summary">
              <span>{filteredIncidents.length} shown</span>
              <span>{stats.totalIncidents} total</span>
            </div>

            {filteredIncidents.length === 0 ? (
              <div className="empty-state">
                <h3>No incidents match this filter</h3>
                <p>Try another severity level or rerun grouping with different input.</p>
              </div>
            ) : (
              <div className="incident-list">
                {filteredIncidents.map((incident) => {
                  const originalIndex = incidents.findIndex(
                    (item) => item.incident_id === incident.incident_id
                  );

                  return (
                    <button
                      key={incident.incident_id}
                      className={`incident-row ${
                        selectedIncidentId === incident.incident_id ? "selected" : ""
                      }`}
                      onClick={() => handleExplain(originalIndex, incident)}
                    >
                      <div className="incident-row-top">
                        <strong>{incident.summary?.title || "Untitled incident"}</strong>
                        <SeverityPill value={incident.priority} />
                      </div>

                      <p className="incident-description">
                        {incident.summary?.description || "No description available."}
                      </p>

                      <div className="incident-row-meta">
                        <span>{incident.group_key}</span>
                        <span>{incident.event_count} event(s)</span>
                        <span>{formatDate(incident.first_seen)}</span>
                      </div>
                    </button>
                  );
                })}
              </div>
            )}
          </section>
        </section>

        <section className="panel detail-panel">
          <div className="panel-header">
            <div>
              <h2>Incident detail</h2>
              <p className="panel-subtitle">
                Structured explain output for the selected incident.
              </p>
            </div>

            <button
              className="button secondary"
              onClick={handleExportSelected}
              disabled={!explainResponse}
            >
              Export JSON
            </button>
          </div>

          {!explainResponse ? (
            <div className="empty-state">
              <h3>No incident selected</h3>
              <p>Select an incident from the list to load explanation details.</p>
            </div>
          ) : (
            <div className="detail-stack">
              <div className="detail-hero">
                <div>
                  <div className="detail-hero-top">
                    <h3>{explainResponse.incident.summary.title}</h3>
                    <SeverityPill value={explainResponse.incident.priority} />
                  </div>
                  <p>{explainResponse.incident.summary.description}</p>
                </div>
              </div>

              <div className="detail-grid">
                <div className="detail-card">
                  <h4>Classification</h4>
                  <ul>
                    <li>Severity: {explainResponse.incident.severity}</li>
                    <li>Confidence: {explainResponse.incident.confidence}</li>
                    <li>Priority: {explainResponse.incident.priority}</li>
                    <li>Pattern: {explainResponse.incident.attack_pattern}</li>
                  </ul>
                </div>

                <div className="detail-card">
                  <h4>Counts</h4>
                  <ul>
                    <li>Events: {explainResponse.incident.event_count}</li>
                    <li>Errors: {explainResponse.incident.error_count}</li>
                    <li>Warnings: {explainResponse.incident.warning_count}</li>
                    <li>Hosts: {explainResponse.incident.distinct_hosts}</li>
                  </ul>
                </div>
              </div>

              <div className="detail-card">
                <h4>Highlights</h4>
                <ul>
                  {explainResponse.incident_evidence.highlights.map((item, idx) => (
                    <li key={idx}>{item}</li>
                  ))}
                </ul>
              </div>

              <div className="detail-card">
                <h4>Sample events</h4>
                <pre>
                  {JSON.stringify(
                    explainResponse.incident_evidence.extra?.sample_events || [],
                    null,
                    2
                  )}
                </pre>
              </div>

              {selectedIncident ? (
                <div className="detail-card subtle-card">
                  <h4>Selected bucket</h4>
                  <ul>
                    <li>Group key: {selectedIncident.group_key}</li>
                    <li>First seen: {formatDate(selectedIncident.first_seen)}</li>
                    <li>Last seen: {formatDate(selectedIncident.last_seen)}</li>
                    <li>Event count: {selectedIncident.event_count}</li>
                  </ul>
                </div>
              ) : null}
            </div>
          )}

          {loadingExplain ? <div className="loading-note">Loading incident detail…</div> : null}
        </section>
      </main>
    </div>
  );
}

export default App;