import React, { useState } from "react";
import { useNavigate } from "react-router-dom";
import { api } from "../api/client.js";

export default function Login() {
  const [mode, setMode] = useState("login"); // "login" | "register"
  const [username, setUsername] = useState("");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [role, setRole] = useState("developer");
  const [error, setError] = useState(null);
  const [loading, setLoading] = useState(false);
  const navigate = useNavigate();

  async function handleSubmit(e) {
    e.preventDefault();
    setError(null);
    setLoading(true);
    try {
      if (mode === "login") {
        await api.login(username, password);
        navigate("/deployments");
      } else {
        await api.register(username, email, password, role);
        setMode("login");
        setError(null);
      }
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="login-wrap card">
      <h2>{mode === "login" ? "Log in" : "Create account"}</h2>
      {error && <div className="error-box">{error}</div>}
      <form onSubmit={handleSubmit}>
        <label>Username</label>
        <input value={username} onChange={(e) => setUsername(e.target.value)} required />

        {mode === "register" && (
          <>
            <label>Email</label>
            <input type="email" value={email} onChange={(e) => setEmail(e.target.value)} required />
          </>
        )}

        <label>Password</label>
        <input type="password" value={password} onChange={(e) => setPassword(e.target.value)} required />

        {mode === "register" && (
          <>
            <label>Role</label>
            <select value={role} onChange={(e) => setRole(e.target.value)}>
              <option value="developer">developer</option>
              <option value="security_reviewer">security_reviewer</option>
              <option value="viewer">viewer</option>
              <option value="admin">admin</option>
            </select>
          </>
        )}

        <button type="submit" disabled={loading}>
          {loading ? "Please wait…" : mode === "login" ? "Log in" : "Register"}
        </button>
      </form>
      <p className="muted" style={{ marginTop: 16 }}>
        {mode === "login" ? (
          <>No account? <a href="#" onClick={(e) => { e.preventDefault(); setMode("register"); }}>Register</a></>
        ) : (
          <>Have an account? <a href="#" onClick={(e) => { e.preventDefault(); setMode("login"); }}>Log in</a></>
        )}
      </p>
    </div>
  );
}
