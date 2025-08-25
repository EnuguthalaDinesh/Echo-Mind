import { getCustomerId } from "./auth";

const BASE_URL = import.meta.env.VITE_API_BASE || "http://localhost:8000";

const token = () => localStorage.getItem("access_token");

async function http(path, { method = "GET", body, headers = {} } = {}) {
  const res = await fetch(`${BASE_URL}${path}`, {
    method,
    headers: {
      "Content-Type": "application/json",
      ...(token() ? { Authorization: `Bearer ${token()}` } : {}),
      ...headers,
    },
    body: body ? JSON.stringify(body) : undefined,
  });

  if (!res.ok) {
    let msg = "Request failed";
    try {
      const data = await res.json();
      msg = data.detail || msg;
    } catch {}
    throw new Error(msg);
  }

  try {
    return await res.json();
  } catch {
    return null;
  }
}

export async function loginApi({ email, password }) {
  return http("/auth/login", {
    method: "POST",
    body: { email, password },
  });
}

export async function registerApi({ name, email, password }) {
  return http("/auth/register", {
    method: "POST",
    body: { name, email, password },
  });
}

export async function sendChat({ domain, message, history, sessionId }) {
  const customerId = getCustomerId();
  const payload = {
    user_query: message,
    session_id: sessionId,
    customer_profile: {
      customer_id: customerId,
      previous_interactions: [],
      purchase_history: [],
      preference_settings: {},
      sentiment_history: [],
      active_case_id: sessionId,
    },
    conversation_history: history,
    shop_id_for_order_lookup: null,
    domain,
  };

  const data = await http("/chat", {
    method: "POST",
    body: payload,
  });
  return data?.bot_response || "…";
}

export async function fetchConversations(customerId) {
  return http(`/history/${customerId}`);
}

export async function fetchConversationHistory(customerId, sessionId) {
  return http(`/history/${customerId}/${sessionId}`);
}

export async function fetchFaqs() {
  return http("/faqs");
}

export async function createFaq(faq) {
  return http("/faqs", { method: "POST", body: faq });
}

export async function getDashboardStats() {
  return http("/admin/stats");
}