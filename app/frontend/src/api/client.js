const API_BASE = import.meta.env.VITE_API_BASE || "/api";

function getToken() {
  return sessionStorage.getItem("access_token");
}

function setToken(token) {
  sessionStorage.setItem("access_token", token);
}

function clearToken() {
  sessionStorage.removeItem("access_token");
}

async function request(path, { method = "GET", body, auth = true, form = false } = {}) {
  const headers = {};
  if (auth) {
    const token = getToken();
    if (token) headers["Authorization"] = `Bearer ${token}`;
  }
  let payload = body;
  if (body && !form) {
    headers["Content-Type"] = "application/json";
    payload = JSON.stringify(body);
  }

  const res = await fetch(`${API_BASE}${path}`, { method, headers, body: payload });
  if (!res.ok) {
    let detail = res.statusText;
    try {
      const err = await res.json();
      detail = err.detail || detail;
    } catch (_) { /* not JSON */ }
    throw new Error(typeof detail === "string" ? detail : JSON.stringify(detail));
  }
  if (res.status === 204) return null;
  return res.json();
}

export const api = {
  async login(username, password) {
    const params = new URLSearchParams();
    params.set("username", username);
    params.set("password", password);
    const data = await request("/auth/login", { method: "POST", body: params, auth: false, form: true });
    setToken(data.access_token);
    return data;
  },
  async register(username, email, password, role = "developer") {
    return request("/auth/register", { method: "POST", body: { username, email, password, role }, auth: false });
  },
  logout() {
    clearToken();
  },
  isAuthenticated() {
    return !!getToken();
  },
  listDeployments(status) {
    const q = status ? `?status=${encodeURIComponent(status)}` : "";
    return request(`/deployments${q}`, { auth: false });
  },
  createDeployment(commit_sha, service_name, environment = "production") {
    return request("/deployments", { method: "POST", body: { commit_sha, service_name, environment } });
  },
  approveDeployment(runId) {
    return request(`/deployments/${runId}/approve`, { method: "POST" });
  },
  stats() {
    return request("/deployments/stats/summary", { auth: false });
  },
};
