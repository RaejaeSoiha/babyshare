// SPA fallback for guest links when the API is hosted separately.
import { useEffect, useState } from "react";
import { apiFetch, apiUrl } from "../lib/api";

type GuestInfo = {
  expiresAt: string;
  label: string;
  original: string;
  passwordRequired: boolean;
};

export default function GuestLogin() {
  const token = new URLSearchParams(window.location.search).get("token") || "";
  const [info, setInfo] = useState<GuestInfo | null>(null);

  useEffect(() => {
    if (!token) return;
    apiFetch(`/api/guest-info/${encodeURIComponent(token)}`)
      .then((response) => response.ok ? response.json() as Promise<GuestInfo> : null)
      .then((data) => data && setInfo(data))
      .catch(() => setInfo(null));
  }, [token]);

  if (!token) {
    return (
      <div className="page auth">
        <div className="auth-card">
          <h1>Invalid link</h1>
          <a href="/">Back to home</a>
        </div>
      </div>
    );
  }

  const name = info?.label || info?.original || "Shared file";
  return (
    <div className="page auth">
      <div className="auth-card">
        <h1>Guest Access</h1>
        <p className="muted">{name}</p>
        {info && !info.passwordRequired ? (
          <div className="file-actions">
            <a className="btn btn-register" href={apiUrl(`/guest-download?token=${encodeURIComponent(token)}&action=preview`)}>Review</a>
            <a className="btn btn-login" href={apiUrl(`/guest-download?token=${encodeURIComponent(token)}&action=download`)}>Download</a>
          </div>
        ) : (
          <form method="POST" action={apiUrl("/guest-login")} className="form">
            <input type="hidden" name="token" value={token} />
            <label>
              Password
              <input type="password" name="password" maxLength={128} placeholder="Enter password" required />
            </label>
            <div className="file-actions">
              <button type="submit" name="action" value="preview" className="btn btn-register">Review</button>
              <button type="submit" name="action" value="download" className="btn btn-login">Download</button>
            </div>
          </form>
        )}
        <div className="auth-links">
          <a href="/guest-upload">Upload another file</a>
          <a href="/">Back to home</a>
        </div>
      </div>
    </div>
  );
}
