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
    <div className="page auth">
      <div className="auth-card wide">
        <h1>Welcome, {me.user}</h1>
        <p className="muted">Upload files and share securely over LAN.</p>

        <form onSubmit={onUpload} encType="multipart/form-data" className="form">
          <label>
            Choose files
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
            {loading ? "Uploading..." : "Upload"}
          </button>
        </form>

        {error && <p className="error">{error}</p>}

        {result && (
          <div className="result-card">
            <h2>Uploaded</h2>
            {result.links.map((link) => (
              <div key={link.url} className="file-row">
                <div>
                  <strong>{link.name}</strong>
                  <div className="meta">{link.hash ? "?? Password protected" : "? Open access"}</div>
                </div>
                <div className="file-actions">
                  <a className="btn btn-register" href={`${link.url}?action=preview`}>Review</a>
                  <a className="btn btn-login" href={`${link.url}?action=download`}>Download</a>
                </div>
              </div>
            ))}
          </div>
        )}

        <div className="cta-row">
          <a className="btn btn-login" href="/files">View My Files</a>
          <a className="btn btn-register" href="/logout">Logout</a>
          {me.isAdmin && <a className="btn btn-guest" href="/admin">Admin Panel</a>}
        </div>
      </div>
    </div>
  );
}
