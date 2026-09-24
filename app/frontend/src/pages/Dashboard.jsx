import React, { useEffect, useState } from "react";

import { api } from "../api/client.js";

export default function Dashboard() {
  const [stats, setStats] = useState(null);
  const [error, setError] = useState(null);

  useEffect(() => {
    api.stats().then(setStats).catch((e) => setError(e.message));
  }, []);

  if (error) return <div className="error-box">{error}</div>;
  if (!stats) return <p className="muted">Loading…</p>;

  return (
    <div>
      <h1>Platform Overview</h1>
      <p className="muted">Live stats pulled from the deployments API ({stats.total} recorded deployment(s)).</p>

      <div className="grid cols-3" style={{ margin: "24px 0" }}>
        <div className="card">
          <h3>Avg. Privacy Risk</h3>
          <div className={`metric ${stats.avg_risk_score < 30 ? "green" : stats.avg_risk_score < 70 ? "orange" : "red"}`}>
            {stats.avg_risk_score}/100
          </div>
        </div>
        <div className="card">
          <h3>Avg. Security Score</h3>
          <div className={`metric ${stats.avg_security_score >= 80 ? "green" : stats.avg_security_score >= 50 ? "orange" : "red"}`}>
            {stats.avg_security_score}/100
          </div>
        </div>
        <div className="card">
          <h3>Total Deployments</h3>
          <div className="metric">{stats.total}</div>
        </div>
      </div>

      <div className="card">
        <h3>By Status</h3>
        <table>
          <thead><tr><th>Status</th><th>Count</th></tr></thead>
          <tbody>
            {Object.entries(stats.by_status).map(([status, count]) => (
              <tr key={status}>
                <td><span className={`badge ${status}`}>{status}</span></td>
                <td>{count}</td>
              </tr>
            ))}
            {Object.keys(stats.by_status).length === 0 && (
              <tr><td colSpan={2} className="muted">No deployments recorded yet.</td></tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}
