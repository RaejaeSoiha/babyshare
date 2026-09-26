const rawBase = (import.meta as ImportMeta).env?.VITE_API_BASE?.trim?.() ?? "";

const normalizeBase = (value: string) => value.replace(/\/+$/, "");

export const apiBase =
  rawBase.length > 0 ? normalizeBase(rawBase) : window.location.origin;

export const apiUrl = (path: string) => {
  if (/^https?:\/\//i.test(path)) return path;
  if (!path.startsWith("/")) return `${apiBase}/${path}`;
  return `${apiBase}${path}`;
};

export const apiFetch = (path: string, init: RequestInit = {}) =>
  fetch(apiUrl(path), { credentials: "include", ...init });

export async function uploadFormData<T>(
  path: string,
  data: FormData,
  onProgress: (percent: number) => void,
  options: { headers?: Record<string, string> } = {},
): Promise<T> {
  return new Promise((resolve, reject) => {
    const request = new XMLHttpRequest();
    request.open("POST", apiUrl(path));
    request.withCredentials = true;
    request.responseType = "text";
    Object.entries(options.headers ?? {}).forEach(([name, value]) => request.setRequestHeader(name, value));
    request.upload.onprogress = (event) => {
      if (event.lengthComputable) onProgress(Math.round((event.loaded / event.total) * 100));
    };
    request.onerror = () => reject(new Error("network_error"));
    request.onload = () => {
      let body: unknown = null;
      try {
        body = request.responseText ? JSON.parse(request.responseText) : null;
      } catch {
        reject(new Error("invalid_response"));
        return;
      }
      if (request.status < 200 || request.status >= 300) {
        const error = typeof body === "object" && body && "error" in body ? String(body.error) : "upload_failed";
        reject(new Error(error));
        return;
      }
      resolve(body as T);
    };
    request.send(data);
  });
}
