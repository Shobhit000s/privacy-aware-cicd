import React from "react";
import { Routes, Route, Navigate, Link, useLocation, useNavigate } from "react-router-dom";
import { api } from "./api/client.js";
import Login from "./pages/Login.jsx";
import Dashboard from "./pages/Dashboard.jsx";
import Deployments from "./pages/Deployments.jsx";

function RequireAuth({ children }) {
  const location = useLocation();
  if (!api.isAuthenticated()) {
    return <Navigate to="/login" state={{ from: location }} replace />;
  }
  return children;
}

function NavBar() {
  const location = useLocation();
  const navigate = useNavigate();
  const authed = api.isAuthenticated();

  return (
    <nav>
      <span className="brand">🔐 Privacy-Aware CI/CD Platform</span>
      <Link to="/" className={location.pathname === "/" ? "active" : ""}>Dashboard</Link>
      <Link to="/deployments" className={location.pathname === "/deployments" ? "active" : ""}>Deployments</Link>
      {authed ? (
        <a href="#" onClick={(e) => { e.preventDefault(); api.logout(); navigate("/login"); }}>Log out</a>
      ) : (
        <Link to="/login" className={location.pathname === "/login" ? "active" : ""}>Log in</Link>
      )}
    </nav>
  );
}

export default function App() {
  return (
    <>
      <NavBar />
      <main>
        <Routes>
          <Route path="/login" element={<Login />} />
          <Route path="/" element={<Dashboard />} />
          <Route
            path="/deployments"
            element={
              <RequireAuth>
                <Deployments />
              </RequireAuth>
            }
          />
        </Routes>
      </main>
    </>
  );
}
