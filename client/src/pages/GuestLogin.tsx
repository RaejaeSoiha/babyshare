// Guest access page (password gate and review/download actions).
import { useEffect, useState } from "react";

type GuestInfo = {
  label: string;
  original: string;
  expiresAt: string;
  passwordRequired: boolean;
};

export default function GuestLogin() {
  const [token, setToken] = useState("");
  const [info, setInfo] = useState<GuestInfo | null>(null);

  // Load share metadata for display (if available).
  useEffect(() => {
    const params = new URLSearchParams(window.location.search);
    const t = params.get("token") || "";
    setToken(t);
    if (!t) return;
    fetch(`/api/guest-info/${t}`)
      .then((res) => res.ok ? res.json() : null)
      .then((data) => data && setInfo(data));
  }, []);

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

        {info && !info.passwordRequired && (
          <div className="file-actions">
            <a className="btn btn-register" href={`/guest-download?token=${token}&action=preview`}>Review</a>
            <a className="btn btn-login" href={`/guest-download?token=${token}&action=download`}>Download</a>
          </div>
        )}

        {(!info || info.passwordRequired) && (
          <form method="POST" action="/guest-login" className="form">
            <input type="hidden" name="token" value={token} />
            <label>
              Password
              <input type="password" name="password" placeholder="Enter password" required />
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
