// Guest upload form that returns a share link + QR code.
import { useState } from "react";

type UploadResult = {
  link: string;
  qrCode: string;
  label: string;
  expires: number;
  passwordRequired: boolean;
};

export default function GuestUpload() {
  const [result, setResult] = useState<UploadResult | null>(null);
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);

  // Post FormData to the guest upload endpoint.
  const onSubmit = async (e: React.FormEvent<HTMLFormElement>) => {
    e.preventDefault();
    setError("");
    setLoading(true);
    const form = e.currentTarget;
    const data = new FormData(form);

    try {
      const res = await fetch("/guest-upload", {
        method: "POST",
        body: data,
      });
      if (!res.ok) throw new Error("Upload failed");
      const json = (await res.json()) as UploadResult;
      setResult(json);
      form.reset();
    } catch (err) {
      setError("Upload failed. Please try again.");
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="page auth">
      <div className="auth-card wide">
        <h1>Guest Upload</h1>
        <p className="muted">Share a file without creating an account.</p>

        <form className="form" onSubmit={onSubmit}>
          <label>
            Select file
            <input type="file" name="file" required />
          </label>
          <label>
            Label (optional)
            <input name="label" placeholder="e.g. Math homework" />
          </label>
          <label>
            Password (optional)
            <input type="password" name="password" placeholder="Protect the file" />
          </label>
          <button type="submit" className="btn btn-guest" disabled={loading}>
            {loading ? "Uploading..." : "Upload"}
          </button>
        </form>

        {error && <p className="error">{error}</p>}

        {result && (
          <div className="result-card">
            <h2>File uploaded</h2>
            <p className="muted">Share this link:</p>
            <a href={result.link} className="link" target="_blank" rel="noreferrer">
              {result.link}
            </a>
            <div className="qr-block">
              <img src={result.qrCode} alt="QR" />
            </div>
            <p className="meta">
              {result.passwordRequired ? "?? Password required" : "? No password required"}
            </p>
          </div>
        )}

        <div className="auth-links">
          <a href="/">Back to home</a>
        </div>
      </div>
    </div>
  );
}
