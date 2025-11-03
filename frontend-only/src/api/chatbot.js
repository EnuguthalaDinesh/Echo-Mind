import axios from "axios";

// 🚨 CRITICAL FIX: The local fallback "http://localhost:8000" is removed
// and replaced with your live Render backend URL.
// This ensures that if the VITE_API_BASE environment variable is missing 
// during the Vercel build, it defaults to the correct public address.
const API_BASE = import.meta?.env?.VITE_API_BASE ?? "https://echo-backend-1-ubeb.onrender.com";

const api = axios.create({
  baseURL: API_BASE,
});

export const register = (data) => api.post(`/register`, data);
export const login = (data) => api.post(`/login`, data);
export const me = (token) => api.get(`/me`, { headers: { Authorization: `Bearer ${token}` } });

export const sendChat = (data) => api.post(`/chat`, data);
export const getCases = (customerId) => api.get(`/cases/${customerId}`);
export const resolveCase = (caseId, summary) =>
  api.post(`/cases/${caseId}/resolve`, summary ? { summary } : {});
export const summarizeCase = (caseId) => api.post(`/cases/${caseId}/summarize`);
export const createTicket = (data) => api.post(`/tickets`, data);
export const listTickets = (customerId) => api.get(`/tickets/${customerId}`);
export const updateTicket = (ticketId, status) =>
  api.patch(`/tickets/${ticketId}`, { status });

// OAuth helpers
export const googleLoginUrl = () => `${API_BASE}/auth/google/login`;
export const githubLoginUrl = () => `${API_BASE}/auth/github/login`;