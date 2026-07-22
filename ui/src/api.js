const DEFAULT_API_BASE_URL = 'http://127.0.0.1:8000';

export const API_BASE_URL = (import.meta.env.VITE_API_BASE_URL || DEFAULT_API_BASE_URL).replace(/\/$/, '');

let accessToken = null;

export function setApiAuthToken(token) {
  accessToken = token || null;
}

function buildUrl(path, params = {}) {
  const url = new URL(`${API_BASE_URL}${path}`);
  Object.entries(params).forEach(([key, value]) => {
    if (value === undefined || value === null || value === '') {
      return;
    }
    if (Array.isArray(value)) {
      value.filter(Boolean).forEach((item) => url.searchParams.append(key, item));
      return;
    }
    url.searchParams.set(key, value);
  });
  return url.toString();
}

function buildHeaders(extraHeaders = {}) {
  const headers = { ...extraHeaders };
  if (accessToken) {
    headers.Authorization = `Bearer ${accessToken}`;
  }
  return headers;
}

async function parsePayload(response) {
  return response.json().catch(() => ({}));
}

export async function apiGet(path, params = {}) {
  const response = await fetch(buildUrl(path, params), {
    headers: buildHeaders(),
  });
  const payload = await parsePayload(response);
  if (!response.ok) {
    throw new Error(payload.detail || `Request failed with status ${response.status}`);
  }
  return payload;
}

export async function apiPost(path, body = {}) {
  const response = await fetch(`${API_BASE_URL}${path}`, {
    method: 'POST',
    headers: buildHeaders({ 'Content-Type': 'application/json' }),
    body: JSON.stringify(body),
  });
  const payload = await parsePayload(response);
  if (!response.ok) {
    throw new Error(payload.detail || `Request failed with status ${response.status}`);
  }
  return payload;
}
