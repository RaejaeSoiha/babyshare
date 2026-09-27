import { useState } from "react";
import { apiUrl, uploadFormData } from "../lib/api";

type UploadResult = {
  downloadPath?: string;
  expires: number;
  label: string;
  link: string;
  passwordRequired: boolean;
  previewPath?: string;
  qrCode: string;
};

type SelectedFile = { name: string; size: number };

function LightningMark() {
  return <svg viewBox="0 0 24 24" aria-hidden="true"><path d="M13.2 1.8 4.6 13h6.1l-.9 9.2L19.4 11h-6.1l-.1-9.2Z" fill="currentColor" /></svg>;
}

function UploadIcon() {
  return <svg viewBox="0 0 24 24" aria-hidden="true"><path d="M12 16V4m0 0L7.7 8.3M12 4l4.3 4.3M5 15.5v3A1.5 1.5 0 0 0 6.5 20h11a1.5 1.5 0 0 0 1.5-1.5v-3" fill="none" stroke="currentColor" strokeLinecap="round" strokeLinejoin="round" strokeWidth="1.7" /></svg>;
}

function ShieldIcon() {
  return <svg viewBox="0 0 24 24" aria-hidden="true"><path d="M12 3 5 6v5.3c0 4.4 3 7.9 7 9.7 4-1.8 7-5.3 7-9.7V6l-7-3Zm-3.2 9 2.1 2.1 4.4-4.4" fill="none" stroke="currentColor" strokeLinecap="round" strokeLinejoin="round" strokeWidth="1.7" /></svg>;
}

function formatFileSize(bytes: number) {
  if (bytes < 1024 * 1024) return `${Math.max(1, Math.round(bytes / 1024))} KB`;
  if (bytes < 1024 * 1024 * 1024) return `${(bytes / (1024 * 1024)).toFixed(bytes >= 100 * 1024 * 1024 ? 0 : 1)} MB`;
  return `${(bytes / (1024 * 1024 * 1024)).toFixed(1)} GB`;
}

export default function GuestUpload() {
  const [result, setResult] = useState<UploadResult | null>(null);
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);
  const [progress, setProgress] = useState(0);
  const [selectedFile, setSelectedFile] = useState<SelectedFile | null>(null);
  const [linkCopied, setLinkCopied] = useState(false);

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
      setSelectedFile(null);
      form.reset();
    } catch (uploadError) {
      setError(uploadError instanceof Error && uploadError.message === "file_too_large"
        ? "The file must be 1 GB or smaller."
        : "Upload failed. Please try again.");
    } finally {
      setLoading(false);
    }
  };

  const copyLink = async () => {
    if (!result) return;
    try {
      await navigator.clipboard.writeText(result.link);
      setLinkCopied(true);
    } catch {
      setError("Could not copy the link. Please copy it from the share page.");
    }
  };

  const uploadAnother = () => {
    setError("");
    setLinkCopied(false);
    setProgress(0);
    setResult(null);
  };

  return (
    <div className="page guest-upload-page">
      <header className="guest-upload-header">
        <a className="guest-upload-brand" href="/" aria-label="BabyShare home">
          <span className="guest-upload-brand-mark"><LightningMark /></span>
          <span>BabyShare</span>
        </a>
        <a className="guest-upload-home-link" href="/">Back to home</a>
      </header>

      <main className="guest-upload-shell">
        {!result ? (
          <section className="guest-upload-card" aria-labelledby="guest-upload-title">
            <div className="guest-upload-icon"><UploadIcon /></div>
            <p className="guest-upload-kicker">ADVANCED UPLOAD</p>
            <h1 id="guest-upload-title">Share with more control.</h1>
            <p className="guest-upload-copy">Add a label or password before creating a private share link.</p>

            <form className="guest-upload-form" onSubmit={onSubmit}>
              <label className="guest-file-field">
                <span>Select file</span>
                <input type="file" name="file" required onChange={(event) => {
                  const file = event.target.files?.[0];
                  setSelectedFile(file ? { name: file.name, size: file.size } : null);
                }} />
              </label>
              {selectedFile && <p className="guest-selected-file" aria-live="polite"><strong>{selectedFile.name}</strong><span>{formatFileSize(selectedFile.size)}</span></p>}
              <label>
                <span>Label <em>optional</em></span>
                <input name="label" maxLength={120} placeholder="e.g. Project brief" />
              </label>
              <label>
                <span>Password <em>optional</em></span>
                <input type="password" name="password" minLength={12} maxLength={128} placeholder="12+ characters" autoComplete="new-password" />
              </label>
              <button type="submit" className="guest-upload-submit" disabled={loading}>
                {loading ? `Uploading ${progress}%` : "Create share link"}
              </button>
            </form>

            {loading && <div className="guest-upload-progress" aria-live="polite"><progress max="100" value={progress} /><span>{progress}%</span></div>}
            {error && <p className="guest-upload-error" role="alert">{error}</p>}

            <div className="guest-upload-notes" aria-label="Guest upload details">
              <span>1 file · up to 1 GB</span>
              <span><ShieldIcon />Password protection available</span>
            </div>
          </section>
        ) : (
          <section className="guest-success-card" aria-live="polite" aria-labelledby="guest-success-title">
            <div className="guest-success-icon"><ShieldIcon /></div>
            <p className="guest-upload-kicker">SHARE LINK READY</p>
            <h1 id="guest-success-title">File uploaded successfully</h1>
            <p>{result.passwordRequired ? "Your share is password protected." : "Your private share link is ready."}</p>
            <div className="guest-success-actions">
              <button type="button" className="guest-copy-link" onClick={() => void copyLink()}>{linkCopied ? "Link copied" : "Copy link"}</button>
              <a href={result.link} target="_blank" rel="noreferrer">Open share page</a>
              <a href={apiUrl(result.downloadPath || result.link)} target="_blank" rel="noreferrer">Download</a>
              <button type="button" className="guest-upload-another" onClick={uploadAnother}>Upload another file</button>
            </div>
            <details className="guest-qr-details">
              <summary>Show QR code</summary>
              <img src={result.qrCode} alt="QR code for the shared file" />
            </details>
            {error && <p className="guest-upload-error" role="alert">{error}</p>}
          </section>
        )}
      </main>
    </div>
  );
}
