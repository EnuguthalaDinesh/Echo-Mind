import axios from "axios";

const API_BASE = import.meta?.env?.VITE_API_BASE ?? "http://localhost:8000";

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