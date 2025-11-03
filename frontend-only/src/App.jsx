import React from 'react';
import { BrowserRouter as Router, Routes, Route } from 'react-router-dom';
import { AuthProvider } from './context/AuthContext';
import { ThemeProvider } from './context/ThemeContext';
import Layout from './components/Layout';
import ProtectedRoute from './components/ProtectedRoute';
import LandingPage from './pages/LandingPage';
import LoginPage from './pages/LoginPage';
import RegisterPage from './pages/RegisterPage';
import Dashboard from './pages/Dashboard';
import AgentDashboard from './pages/AgentDashboard';
import ChatPage from './pages/ChatPage';
import AdminDashboard from './pages/AdminDashboard';
// CRITICAL FIX: Import the AuthCallback component
import AuthCallback from './pages/AuthCallback'; 

function App() {
  return (
    <ThemeProvider>
      <AuthProvider>
        <Router>
          <Layout>
            <Routes>
              {/* Public Routes */}
              <Route path="/" element={<LandingPage />} />
              <Route path="/login" element={<LoginPage />} />
              <Route path="/register" element={<RegisterPage />} />
              
              {/* CRITICAL FIX: OAuth Callback Route */}
              <Route path="/auth/callback" element={<AuthCallback />} />
              
              {/* Public Dashboard Routes (Needs to be cleaned up or protected below) */}
              {/* NOTE: You have duplicate routes below. Keep the ProtectedRoute versions. */}
              <Route path="/admin-dashboard" element={<AdminDashboard />} />
              <Route path="/agent-dashboard" element={<AgentDashboard />} />
              <Route path="/dashboard" element={<Dashboard />} />

              {/* Allow public access to chat if you want */}
              <Route path="/chat/:domain" element={<ChatPage />} />

              {/* Protected Admin Dashboard */}
              <Route
                path="/admin-dashboard"
                element={
                  <ProtectedRoute requireAdmin={true}>
                    <AdminDashboard />
                  </ProtectedRoute>
                }
              />

              {/* Protected Agent Dashboard */}
              <Route
                path="/agent-dashboard"
                element={
                  <ProtectedRoute requireAgent={true}>
                    <AgentDashboard />
                  </ProtectedRoute>
                }
              />

              {/* Protected User Dashboard */}
              <Route
                path="/dashboard"
                element={
                  <ProtectedRoute>
                    <Dashboard />
                  </ProtectedRoute>
                }
              />

              {/* Legacy explicit admin separate route if you want */}
              <Route
                path="/admin"
                element={
                  <ProtectedRoute requireAdmin={true}>
                    <AdminDashboard />
                  </ProtectedRoute>
                }
              />

              {/* Catch all route - redirect to landing */}
              <Route path="*" element={<LandingPage />} />
            </Routes>
          </Layout>
        </Router>
      </AuthProvider>
    </ThemeProvider>
  );
}

export default App;