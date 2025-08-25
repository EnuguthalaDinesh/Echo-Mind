import React from "react";
import ReactDOM from "react-dom/client";
import { BrowserRouter, Routes, Route, Navigate } from "react-router-dom";
import "./index.css";
import App from "./pages/App";
import Chat from "./pages/Chat";
import Dashboard from "./pages/Dashboard";
import FAQ from "./pages/FAQ";
import Login from "./pages/Login";
import Register from "./pages/Register";
import { isAuthenticated } from "./services/auth";

function PrivateRoute({ children }) {
  const isAuth = isAuthenticated();
  return isAuth ? children : <Navigate to="/login" replace />;
}

ReactDOM.createRoot(document.getElementById("root")).render(
  <BrowserRouter>
    <Routes>
      <Route path="/" element={<App />} />
      <Route path="/chat/:domain" element={
        <PrivateRoute>
          <Chat />
        </PrivateRoute>
      } />
      <Route path="/faq" element={<FAQ />} />
      <Route path="/login" element={<Login />} />
      <Route path="/register" element={<Register />} />
      <Route path="/dashboard" element={
        <PrivateRoute>
          <Dashboard />
        </PrivateRoute>
      } />
    </Routes>
  </BrowserRouter>
);