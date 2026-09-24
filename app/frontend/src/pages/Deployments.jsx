import React, { useEffect, useState } from "react";
import { api } from "../api/client.js";

export default function Deployments() {
  const [deployments, setDeployments] = useState([]);
  const [error, setError] = useState(null);
  const [commitSha, setCommitSha] = useState("");
  const [serviceName, setServiceName] = useState("privacy-aware-app");
  const [creating, setCreating] = useState(false);

  async function refresh() {
    try {
      const data = await api.listDeployments();
      setDeployments(data);
    } catch (e) {
      setError(e.message);
    }
  }

  useEffect(() => { refresh(); }, []);

  async function handleCreate(e) {
    e.preventDefault();
    setCreating(true);
    setError(null);
    try {
      await api.createDeployment(commitSha, serviceName);
      setCommitSha("");
      await refresh();
    } catch (err) {
      setError(err.message);
    } finally {
      setCreating(false);
    }
  }

  async function handleApprove(runId) {
    try {
      await api.approveDeployment(runId);
      await refresh();
    } catch (err) {
      setError(err.message);
    }
  }

  return (
    <div>
      <h1>Deployments</h1>
      {error && <div className="error-box">{error}</div>}

      <div className="grid cols-2" style={{ alignItems: "start", marginBottom: 24 }}>
        <form onSubmit={handleCreate} className="card">
          <h3>Register a deployment</h3>
          <label>Commit SHA</label>
          <input value={commitSha} onChange={(e) => setCommitSha(e.target.value)} required placeholder="abc1234" />
          <label>Service name</label>
          <input value={serviceName} onChange={(e) => setServiceName(e.target.value)} required />
          <button type="submit" disabled={creating}>{creating ? "Creating…" : "Create"}</button>
        </form>
        <div className="card">
          <h3>About this table</h3>
          <p className="muted">
            Deployments are created here (or by the CI pipeline via <code>POST /api/deployments</code>),
            then updated with risk/security scores as each pipeline stage runs
            (<code>PATCH /api/deployments/&#123;run_id&#125;</code>). HIGH/CRITICAL-risk deployments
            can be manually overridden here by an admin or security_reviewer.
          </p>
        </div>
      </div>

      <div className="card">
        <table>
          <thead>
            <tr>
              <th>Run ID</th><th>Service</th><th>Commit</th><th>Risk</th><th>Security</th><th>Status</th><th></th>
            </tr>
          </thead>
          <tbody>
            {deployments.map((d) => (
              <tr key={d.run_id}>
                <td><code>{d.run_id}</code></td>
                <td>{d.service_name}</td>
                <td><code>{d.commit_sha.slice(0, 8)}</code></td>
                <td>{d.risk_score ?? "—"}</td>
                <td>{d.security_score ?? "—"}</td>
                <td><span className={`badge ${d.status}`}>{d.status}</span></td>
                <td>
                  {(d.risk_level === "HIGH" || d.risk_level === "CRITICAL") && d.status !== "approved_override" && (
                    <button onClick={() => handleApprove(d.run_id)}>Override &amp; approve</button>
                  )}
                </td>
              </tr>
            ))}
            {deployments.length === 0 && (
              <tr><td colSpan={7} className="muted">No deployments yet.</td></tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}
