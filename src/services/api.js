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
  // Expected FastAPI: POST /auth/login -> { access_token }
  return http("/auth/login", {
    method: "POST",
    body: { email, password },
  });
}

export async function registerApi({ name, email, password }) {
  // Expected FastAPI: POST /auth/register -> { access_token } or { ok: true }
  return http("/auth/register", {
    method: "POST",
    body: { name, email, password },
  });
}

export async function sendChat({ domain, message, history = [] }) {
  // Expected FastAPI: POST /chat -> { reply }
  const data = await http("/chat", {
    method: "POST",
    body: { domain, message, history },
  });
  return data?.reply || "…";
}

export async function fetchFaqs() {
  // Expected FastAPI: GET /faqs -> [{q,a}]
  return http("/faqs");
}

export async function createFaq(faq) {
  return http("/faqs", { method: "POST", body: faq });
}

export async function getDashboardStats() {
  // Expected FastAPI: GET /admin/stats
  return http("/admin/stats");
}
