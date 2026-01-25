// Authenticated dashboard: upload files and show share links.
import { useEffect, useState } from "react";

type Me = { user: string; isAdmin: boolean };

type UploadLink = { name: string; url: string; qr: string; hash: string | null };

type UploadResult = { links: UploadLink[] };

export default function Dashboard() {
  const [me, setMe] = useState<Me | null>(null);
  const [result, setResult] = useState<UploadResult | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");

  // Fetch session info on load.
  useEffect(() => {
    fetch("/api/me")
      .then((res) => {
        if (res.status === 401) {
          window.location.href = "/login";
          return null;
        }
        return res.json();
      })
      .then((data) => {
        if (data) setMe(data);
      });
  }, []);

  // Post files to /upload (server returns share links as JSON).
  const onUpload = async (e: React.FormEvent<HTMLFormElement>) => {
    e.preventDefault();
    setError("");
    setLoading(true);
    const form = e.currentTarget;
    const data = new FormData(form);
    try {
      const res = await fetch("/upload", { method: "POST", body: data });
      if (!res.ok) throw new Error("upload failed");
      const json = (await res.json()) as UploadResult;
      setResult(json);
      form.reset();
    } catch {
      setError("Upload failed. Try again.");
    } finally {
      setLoading(false);
    }
  };

  if (!me) {
    return (
      <div className="page auth">
        <div className="auth-card">
          <h1>Loading...</h1>
        </div>
      </div>
    );
  }

  return (
    <div className="page dashboard">
      <section className="dashboard-shell">
        <header className="dashboard-header">
          <div>
            <p className="eyebrow">BabyShare Console</p>
            <h1>
              Welcome back, <span>{me.user}</span>
            </h1>
            <p className="muted">Upload, encrypt, and share across your LAN in seconds.</p>
          </div>
          <div className="dashboard-actions">
            <a className="btn btn-login" href="/files">File Vault</a>
            <a className="btn btn-register" href="/logout">Logout</a>
            {me.isAdmin && <a className="btn btn-guest" href="/admin">Admin Panel</a>}
          </div>
        </header>

        <div className="dashboard-grid">
          <div className="dashboard-card upload-panel">
            <div className="panel-head">
              <h2>New Share</h2>
              <span className="pill">Encrypted</span>
            </div>
            <p className="muted">
              Drop multiple files, set an optional label and password, then share the generated links.
            </p>

            <form onSubmit={onUpload} encType="multipart/form-data" className="form form-split">
              <label>
                Select files
                <input type="file" name="files" multiple required />
              </label>
              <label>
                Label (optional)
                <input name="label" placeholder="e.g. Homework files" />
              </label>
              <label>
                Password (optional)
                <input type="password" name="password" placeholder="Protect this upload" />
              </label>
              <button type="submit" className="btn btn-guest" disabled={loading}>
                {loading ? "Uploading..." : "Create Share"}
              </button>
            </form>

            {error && <p className="error">{error}</p>}
          </div>

          <div className="dashboard-card insights-panel">
            <h3>Share Rules</h3>
            <ul className="insight-list">
              <li>Links expire after 30 days for signed-in uploads.</li>
              <li>Guest shares expire after 24 hours by default.</li>
              <li>Use passwords for sensitive files or photos.</li>
            </ul>
            <div className="signal-box">
              <span>LAN Status</span>
              <strong>Online · Ready</strong>
            </div>
          </div>
        </div>

        {result && (
          <section className="dashboard-card share-results">
            <div className="panel-head">
              <h2>Share Links</h2>
              <span className="pill alt">Ready</span>
            </div>
            <div className="share-grid">
              {result.links.map((link) => (
                <div key={link.url} className="share-row">
                  <div>
                    <strong>{link.name}</strong>
                    <div className="meta">{link.hash ? "?? Password protected" : "? Open access"}</div>
                    <div className="share-link">{link.url}</div>
                  </div>
                  <div className="file-actions">
                    <a className="btn btn-register" href={`${link.url}?action=preview`}>Review</a>
                    <a className="btn btn-login" href={`${link.url}?action=download`}>Download</a>
                  </div>
                </div>
              ))}
            </div>
          </section>
        )}
      </section>
    </div>
  );
}
