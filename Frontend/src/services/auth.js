const TOKEN_KEY = "access_token";
const CUSTOMER_ID_KEY = "customer_id";

export function getToken() {
  return localStorage.getItem(TOKEN_KEY);
}

export function setToken(token) {
  localStorage.setItem(TOKEN_KEY, token);
}

export function clearToken() {
  localStorage.removeItem(TOKEN_KEY);
}

export function getCustomerId() {
  return localStorage.getItem(CUSTOMER_ID_KEY);
}

export function setCustomerId(id) {
  localStorage.setItem(CUSTOMER_ID_KEY, id);
}

export function clearCustomerId() {
  localStorage.removeItem(CUSTOMER_ID_KEY);
}

export function isAuthenticated() {
  return !!getToken() && !!getCustomerId();
}