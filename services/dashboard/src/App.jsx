import { useCallback, useEffect, useMemo, useState } from 'react';

const API_BASE = import.meta.env.VITE_API_URL || 'http://localhost:8080';
const DATA_TYPES = ['CREDIT_CARD', 'EMAIL', 'PHONE'];

function Chart({ title, rows, color = '#38bdf8' }) {
  const max = Math.max(...rows.map((row) => row.value), 1);
  const points = rows.map((row, index) => `${(index / Math.max(rows.length - 1, 1)) * 100},${92 - (row.value / max) * 78}`).join(' ');
  return <div className="chart-card"><div className="chart-heading"><h3>{title}</h3><span>{rows.reduce((sum, row) => sum + row.value, 0)}</span></div>{rows.length ? <><svg viewBox="0 0 100 100" preserveAspectRatio="none" role="img" aria-label={title}><line x1="0" y1="92" x2="100" y2="92" className="chart-axis" /><polyline points={points} fill="none" stroke={color} strokeWidth="3" vectorEffect="non-scaling-stroke" /></svg><div className="chart-labels">{rows.slice(-4).map((row) => <small key={row.label}>{row.label.replace('T', ' ').slice(5, 16)}: {row.value}</small>)}</div></> : <p className="empty">Aucune donnée pour ces filtres.</p>}</div>;
}

function App() {
  const [health, setHealth] = useState(null);
  const [metrics, setMetrics] = useState(null);
  const [keys, setKeys] = useState([]);
  const [auditLogs, setAuditLogs] = useState([]);
  const [result, setResult] = useState(null);
  const [inputValue, setInputValue] = useState('4532 1234 5678 9012');
  const [selectedType, setSelectedType] = useState(DATA_TYPES[0]);
  const [newKey, setNewKey] = useState({ name: 'Demo Partner', scope: 'TOKENIZE,DETOKENIZE', quotaPerMinute: 60 });
  const [isRevealed, setIsRevealed] = useState(false);
  const [accessToken, setAccessToken] = useState(() => sessionStorage.getItem('vault-jwt') || '');
  const [credentials, setCredentials] = useState({ email: 'admin@securevault.local', password: '' });
  const [filters, setFilters] = useState({ from: new Date(Date.now() - 86400000).toISOString().slice(0, 16), to: new Date().toISOString().slice(0, 16), clientId: '', action: '' });
  const [analytics, setAnalytics] = useState({ volume: [], actions: [], statuses: [] });
  const [error, setError] = useState('');
  const [activeKey, setActiveKey] = useState('');

  const query = useMemo(() => new URLSearchParams(Object.entries(filters).filter(([, value]) => value)).toString(), [filters]);
  const authHeaders = useMemo(() => ({ Authorization: `Bearer ${accessToken}` }), [accessToken]);

  const fetchData = useCallback(async () => {
    if (!accessToken) return;
    try {
      const [healthRes, metricsRes, keysRes, auditRes, analyticsRes] = await Promise.all([
        fetch(`${API_BASE}/health`),
        fetch(`${API_BASE}/api/v1/metrics?${query}`, { headers: authHeaders }),
        fetch(`${API_BASE}/api/v1/keys`, { headers: authHeaders }),
        fetch(`${API_BASE}/api/v1/audit?${query}`, { headers: authHeaders }),
        fetch(`${API_BASE}/api/v1/analytics?${query}`, { headers: authHeaders }),
      ]);
      if ([metricsRes, keysRes, auditRes, analyticsRes].some((response) => response.status === 401)) throw new Error('Session expirée.');
      setHealth(healthRes.ok ? await healthRes.json() : { status: 'error' });
      setMetrics(metricsRes.ok ? await metricsRes.json() : { totalTokens: 0, requests: 0, avgLatencyMs: 0, successRate: 0 });
      setKeys(keysRes.ok ? await keysRes.json() : []);
      setAuditLogs(auditRes.ok ? await auditRes.json() : []);
      setAnalytics(analyticsRes.ok ? await analyticsRes.json() : { volume: [], actions: [], statuses: [] });
      setError('');
    } catch (error) {
      setHealth({ status: 'offline', message: 'Gateway unavailable' });
      setError(error.message || 'Impossible de charger les données.');
    }
  }, [accessToken, authHeaders, query]);

  useEffect(() => {
    fetchData();
    const iv = setInterval(fetchData, 15000);
    return () => clearInterval(iv);
  }, [fetchData]);

  const handleLogin = async (event) => {
    event.preventDefault();
    const response = await fetch(`${API_BASE}/api/v1/auth/login`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(credentials) });
    if (!response.ok) { setError('Identifiants invalides.'); return; }
    const body = await response.json(); sessionStorage.setItem('vault-jwt', body.accessToken); setAccessToken(body.accessToken); setError('');
  };

  const handleTokenize = async () => {
    try {
      const response = await fetch(`${API_BASE}/api/v1/tokenize`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'X-API-Key': activeKey },
        body: JSON.stringify({ type: selectedType, value: inputValue }),
      });
      const body = await response.json(); if (!response.ok) throw new Error(body.error || 'Tokenisation refusée');
      setResult({ mode: 'tokenize', ...body });
      setIsRevealed(false);
      fetchData();
    } catch (error) {
      setResult({ mode: 'tokenize', error: 'Erreur de connexion au gateway' });
    }
  };

  const handleDetokenize = async () => {
    if (!result || !result.token) return;
    try {
      const response = await fetch(`${API_BASE}/api/v1/detokenize`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'X-API-Key': activeKey },
        body: JSON.stringify({ token: result.token }),
      });
      const body = await response.json(); if (!response.ok) throw new Error(body.error || 'Détokenisation refusée');
      setResult({ ...result, reveal: body.value || 'Aucune correspondance', mode: 'detokenize' });
      setIsRevealed(true);
      fetchData();
    } catch (error) {
      setResult({ ...result, reveal: 'Erreur', mode: 'detokenize' });
    }
  };

  const handleCreateKey = async (event) => {
    event.preventDefault();
    try {
      const response = await fetch(`${API_BASE}/api/v1/keys`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', ...authHeaders },
        body: JSON.stringify({ ...newKey }),
      });
      if (response.ok) {
        const body = await response.json();
        setActiveKey(body.apiKey);
        setNewKey({ name: '', scope: 'TOKENIZE,DETOKENIZE', quotaPerMinute: 60 });
        fetchData();
      }
    } catch (error) {
      console.error(error);
    }
  };

  const tokenPreview = useMemo(() => {
    if (!result || !result.token) return '—';
    return result.token;
  }, [result]);

  if (!accessToken) return <main className="login-shell"><form className="login-card" onSubmit={handleLogin}><p className="eyebrow">Secure Vault</p><h1>Accès administration</h1><label>Email<input type="email" value={credentials.email} onChange={(event) => setCredentials({ ...credentials, email: event.target.value })} /></label><label>Mot de passe<input type="password" required value={credentials.password} onChange={(event) => setCredentials({ ...credentials, password: event.target.value })} /></label>{error && <p className="error">{error}</p>}<button type="submit">Se connecter</button></form></main>;

  return (
    <div className="app-shell">
      <header className="topbar">
        <div>
          <p className="eyebrow">Zero Trust • Token Vault</p>
          <h1>Secure Vault Tokenizer</h1>
        </div>
        <div className="status-pill">
          <span className={`dot ${health?.status === 'ok' ? 'ok' : 'warn'}`} />
          {health?.status === 'ok' ? 'Services en ligne' : 'Vérification...'}
        </div>
      </header>

      <section className="stats-grid">
        <div className="stat-card">
          <span>Tokens actifs</span>
          <strong>{metrics?.totalTokens ?? 248}</strong>
        </div>
        <div className="stat-card">
          <span>Requêtes filtrées</span>
          <strong>{metrics?.requests ?? 0}</strong>
        </div>
        <div className="stat-card">
          <span>Latence moyenne</span>
          <strong>{metrics?.avgLatencyMs ?? 43} ms</strong>
        </div>
        <div className="stat-card"><span>Taux de succès</span><strong>{metrics?.successRate ?? 0}%</strong></div>
      </section>

      <section className="panel filters"><h2>Filtres d’analyse</h2><label>Du<input type="datetime-local" value={filters.from} onChange={(event) => setFilters({ ...filters, from: event.target.value })} /></label><label>Au<input type="datetime-local" value={filters.to} onChange={(event) => setFilters({ ...filters, to: event.target.value })} /></label><label>Client<select value={filters.clientId} onChange={(event) => setFilters({ ...filters, clientId: event.target.value })}><option value="">Tous</option>{keys.map((key) => <option key={key.id} value={key.id}>{key.name}</option>)}</select></label><label>Action<select value={filters.action} onChange={(event) => setFilters({ ...filters, action: event.target.value })}><option value="">Toutes</option><option value="TOKENIZE">TOKENIZE</option><option value="DETOKENIZE">DETOKENIZE</option></select></label><button onClick={fetchData}>Actualiser</button></section>
      {error && <p className="error">{error}</p>}

      <section className="charts-grid"><Chart title="Volume horaire" rows={analytics.volume} /><Chart title="Actions" rows={analytics.actions} color="#22c55e" /><Chart title="Statuts" rows={analytics.statuses} color="#facc15" /></section>

      <main className="content-grid">
        <section className="panel">
          <h2>Playground</h2>
          <div className="field-row">
            <label>
              Type
              <select value={selectedType} onChange={(e) => setSelectedType(e.target.value)}>
                {DATA_TYPES.map((type) => (
                  <option key={type} value={type}>{type}</option>
                ))}
              </select>
            </label>
            <button onClick={handleTokenize}>Tokenize</button>
          </div>
          <label class="label-margin-bot">Clé API active<input type="password" placeholder="Créez une clé ou collez-la ici" value={activeKey} onChange={(event) => setActiveKey(event.target.value)} /></label>

          <textarea value={inputValue} onChange={(e) => setInputValue(e.target.value)} rows={4} />

          <div className="result-box">
            <p className="label">Jeton généré</p>
            <code>{tokenPreview}</code>
          </div>

          <button className="secondary" onClick={handleDetokenize}>Reveal</button>

          <div className="reveal-box">
            <p className="label">Valeur d’origine</p>
            {isRevealed ? <code>{result?.reveal || '—'}</code> : <span className="masked">••••••••••••••••</span>}
          </div>
        </section>

        <section className="panel">
          <h2>API Keys</h2>
          <form onSubmit={handleCreateKey} className="key-form">
            <input
              placeholder="Nom du client"
              value={newKey.name}
              onChange={(e) => setNewKey({ ...newKey, name: e.target.value })}
            />
            <select
              value={newKey.scope}
              onChange={(e) => setNewKey({ ...newKey, scope: e.target.value })}
            >
              <option value="TOKENIZE">TOKENIZE</option>
              <option value="DETOKENIZE">DETOKENIZE</option>
              <option value="TOKENIZE,DETOKENIZE">TOKENIZE + DETOKENIZE</option>
            </select>
            <input
              type="number"
              min="1"
              value={newKey.quotaPerMinute}
              onChange={(e) => setNewKey({ ...newKey, quotaPerMinute: Number(e.target.value) })}
            />
            <button type="submit">Créer</button>
          </form>

          <ul className="key-list">
            {keys.map((key) => (
              <li key={key.id}>
                <div>
                  <strong>{key.name}</strong>
                  <small>{key.scope}</small>
                </div>
                <span>{key.quotaPerMinute}/min</span>
              </li>
            ))}
          </ul>
        </section>

        <section className="panel full-span">
          <h2>Audit log</h2>
          <table>
            <thead>
              <tr>
                <th>Client</th>
                <th>Action</th>
                <th>Statut</th>
                <th>Timestamp</th>
                <th>Latence</th>
              </tr>
            </thead>
            <tbody>
              {auditLogs.map((log) => (
                <tr key={`${log.clientId}-${log.timestamp}`}>
                  <td>{log.clientId}</td>
                  <td>{log.action}</td>
                  <td>{log.status}</td>
                  <td>{new Date(log.timestamp).toLocaleString()}</td>
                  <td>{log.durationMs} ms</td>
                </tr>
              ))}
            </tbody>
          </table>
        </section>
      </main>
    </div>
  );
}

export default App;
