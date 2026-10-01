import { apiFetch } from "./api";

export type QrPairingStatus = "waiting" | "claimed" | "accepted" | "complete" | "cancelled";

export type QrPairing = {
  expiresAt: number;
  file: {
    name: string;
    size: number;
  };
  status: QrPairingStatus;
};

export type QrCredentials = {
  pairToken: string;
  role: "sender" | "receiver";
  secret: string;
};

export type QrSignal = {
  candidate?: RTCIceCandidateInit;
  description?: RTCSessionDescriptionInit;
  sessionId: string;
  type: "offer" | "answer" | "candidate" | "hangup";
};

type PairingResponse = { pairing: QrPairing };

const jsonHeaders = { "Content-Type": "application/json" };

async function responseJson<T>(response: Response): Promise<T> {
  const payload = await response.json().catch(() => ({})) as { error?: string };
  if (!response.ok) throw new Error(payload.error || "qr_pairing_failed");
  return payload as T;
}

function credentialsHeaders(credentials: QrCredentials) {
  return {
    "x-babyshare-qr-role": credentials.role,
    "x-babyshare-qr-secret": credentials.secret,
  };
}

export const QR_PEER_CONFIG: RTCConfiguration = {
  iceServers: [{ urls: "stun:stun.cloudflare.com:3478" }],
};

export async function createQrPairing(file: File) {
  const response = await apiFetch("/api/qr/pairings", {
    body: JSON.stringify({ file: { name: file.name, size: file.size } }),
    headers: jsonHeaders,
    method: "POST",
  });
  return responseJson<{ expiresAt: number; pairToken: string; senderSecret: string; url: string }>(response);
}

export async function claimQrPairing(pairToken: string, existingSecret?: string) {
  const response = await apiFetch(`/api/qr/pairings/${encodeURIComponent(pairToken)}/claim`, {
    body: JSON.stringify({}),
    headers: { ...jsonHeaders, ...(existingSecret ? { "x-babyshare-qr-secret": existingSecret } : {}) },
    method: "POST",
  });
  return responseJson<{ pairing: QrPairing; receiverSecret: string }>(response);
}

export async function readQrPairing(credentials: QrCredentials) {
  const response = await apiFetch(`/api/qr/pairings/${encodeURIComponent(credentials.pairToken)}/status`, {
    headers: credentialsHeaders(credentials),
  });
  return responseJson<PairingResponse>(response);
}

export async function acceptQrPairing(credentials: QrCredentials) {
  const response = await apiFetch(`/api/qr/pairings/${encodeURIComponent(credentials.pairToken)}/accept`, {
    body: JSON.stringify({}),
    headers: { ...jsonHeaders, ...credentialsHeaders(credentials) },
    method: "POST",
  });
  return responseJson<PairingResponse>(response);
}

export async function sendQrSignal(credentials: QrCredentials, signal: QrSignal) {
  const response = await apiFetch(`/api/qr/pairings/${encodeURIComponent(credentials.pairToken)}/signals`, {
    body: JSON.stringify({ signal }),
    headers: { ...jsonHeaders, ...credentialsHeaders(credentials) },
    method: "POST",
  });
  return responseJson<{ ok: true }>(response);
}

export async function takeQrSignals(credentials: QrCredentials) {
  const response = await apiFetch(`/api/qr/pairings/${encodeURIComponent(credentials.pairToken)}/signals`, {
    headers: credentialsHeaders(credentials),
  });
  return responseJson<{ signals: QrSignal[] }>(response);
}

export async function completeQrPairing(credentials: QrCredentials) {
  const response = await apiFetch(`/api/qr/pairings/${encodeURIComponent(credentials.pairToken)}/complete`, {
    body: JSON.stringify({}),
    headers: { ...jsonHeaders, ...credentialsHeaders(credentials) },
    method: "POST",
  });
  return responseJson<PairingResponse>(response);
}
