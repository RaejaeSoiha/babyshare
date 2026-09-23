// Guest upload form that returns a share link and QR code.
import { useState } from "react";
import { uploadFormData } from "../lib/api";

type UploadResult = {
  expires: number;
  label: string;
  link: string;
  passwordRequired: boolean;
  qrCode: string;
};

export default function GuestUpload() {
  const [result, setResult] = useState<UploadResult | null>(null);
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);
  const [progress, setProgress] = useState(0);

  const onSubmit = async (event: React.FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    setError("");
    setLoading(true);
    setProgress(0);
    const form = event.currentTarget;
    const data = new FormData(form);
    const file = data.get("file");
    if (file instanceof File && file.size > 1024 * 1024 * 1024) {
      setError("The file must be 1 GB or smaller.");
      setLoading(false);
      return;
    }

    try {
      const upload = await uploadFormData<UploadResult>("/guest-upload", data, setProgress);
      setResult(upload);
      form.reset();
    } catch (uploadError) {
      setError(uploadError instanceof Error && uploadError.message === "file_too_large"
        ? "The file must be 1 GB or smaller."
        : "Upload failed. Please try again.");
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
            <input name="label" maxLength={120} placeholder="e.g. Math homework" />
          </label>
          <label>
            Password (optional)
            <input type="password" name="password" minLength={12} maxLength={128} placeholder="12+ characters to protect the file" />
          </label>
          <button type="submit" className="btn btn-guest" disabled={loading}>
            {loading ? "Uploading..." : "Upload"}
          </button>
        </form>

        {loading && (
          <div className="upload-progress" aria-live="polite">
            <progress max="100" value={progress} />
            <span>Uploading {progress}%</span>
          </div>
        )}
        {error && <p className="error" role="alert">{error}</p>}

        {result && (
          <div className="result-card">
            <h2>File uploaded</h2>
            <p className="muted">Share this link:</p>
            <a href={result.link} className="link" target="_blank" rel="noreferrer">{result.link}</a>
            <div className="qr-block">
              <img src={result.qrCode} alt="QR code for the shared file" />
            </div>
            <p className="meta">{result.passwordRequired ? "Password required" : "No password required"}</p>
          </div>
        )}

        <div className="auth-links">
          <a href="/">Back to home</a>
        </div>
      </div>
    </div>
  );
}
