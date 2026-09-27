// Authenticated workspace for creating encrypted links and reaching account controls.
import { useEffect, useRef, useState } from "react";
import type { ChangeEvent, DragEvent } from "react";
import { Link } from "react-router-dom";
import { apiFetch, uploadFormData } from "../lib/api";

type Me = { user: string; isAdmin: boolean };
type UploadLink = { expires: number; name: string; passwordRequired: boolean; qr: string; url: string };
type UploadResult = { links: UploadLink[] };

const MAX_FILE_SIZE = 1024 * 1024 * 1024;

function formatFileSize(bytes: number) {
  if (bytes < 1024) return `${bytes} B`;
  const units = ["KB", "MB", "GB"];
  const unitIndex = Math.min(Math.floor(Math.log(bytes) / Math.log(1024)) - 1, units.length - 1);
  const value = bytes / (1024 ** (unitIndex + 1));
  return `${value >= 10 ? value.toFixed(0) : value.toFixed(1)} ${units[unitIndex]}`;
}

function UploadIcon() {
  return (
    <svg viewBox="0 0 24 24" aria-hidden="true">
      <path d="M12 16V4m0 0L7.8 8.2M12 4l4.2 4.2M5 15.5v3A1.5 1.5 0 0 0 6.5 20h11a1.5 1.5 0 0 0 1.5-1.5v-3" fill="none" stroke="currentColor" strokeLinecap="round" strokeLinejoin="round" strokeWidth="1.7" />
    </svg>
  );
}

function FileIcon() {
  return (
    <svg viewBox="0 0 24 24" aria-hidden="true">
      <path d="M7 3.5h6l4 4V20a1 1 0 0 1-1 1H7a1 1 0 0 1-1-1V4.5a1 1 0 0 1 1-1Zm5.5 0V8H17" fill="none" stroke="currentColor" strokeLinecap="round" strokeLinejoin="round" strokeWidth="1.6" />
    </svg>
  );
}

function ShieldIcon() {
  return (
    <svg viewBox="0 0 24 24" aria-hidden="true">
      <path d="M12 3 5 6v5.2c0 4.5 3 8 7 9.8 4-1.8 7-5.3 7-9.8V6l-7-3Zm-3 9 2 2 4.4-4.4" fill="none" stroke="currentColor" strokeLinecap="round" strokeLinejoin="round" strokeWidth="1.7" />
    </svg>
  );
}

function ArrowIcon() {
  return (
    <svg viewBox="0 0 24 24" aria-hidden="true">
      <path d="M5 12h13m-5-5 5 5-5 5" fill="none" stroke="currentColor" strokeLinecap="round" strokeLinejoin="round" strokeWidth="1.8" />
    </svg>
  );
}

function expiryLabel(expires: number) {
  const remainingDays = Math.max(1, Math.ceil((expires - Date.now()) / (24 * 60 * 60 * 1000)));
  return `Expires in ${remainingDays} ${remainingDays === 1 ? "day" : "days"}`;
}

export default function Dashboard() {
  const inputRef = useRef<HTMLInputElement>(null);
  const [me, setMe] = useState<Me | null>(null);
  const [result, setResult] = useState<UploadResult | null>(null);
  const [files, setFiles] = useState<File[]>([]);
  const [label, setLabel] = useState("");
  const [password, setPassword] = useState("");
  const [dragging, setDragging] = useState(false);
  const [loading, setLoading] = useState(false);
  const [progress, setProgress] = useState(0);
  const [copiedUrl, setCopiedUrl] = useState("");
  const [error, setError] = useState("");

  useEffect(() => {
    apiFetch("/api/me")
      .then((res) => {
        if (res.status === 401) {
          window.location.assign("/login");
          return null;
        }
        if (!res.ok) throw new Error("account_load_failed");
        return res.json() as Promise<Me>;
      })
      .then((data) => data && setMe(data))
      .catch(() => setError("Unable to load your account. Refresh the page and try again."));
  }, []);

  const chooseFiles = (nextFiles: FileList | File[]) => {
    const selected = Array.from(nextFiles);
    setError("");
    setCopiedUrl("");
    if (selected.length === 0) return;
    if (selected.length > 20) {
      setFiles([]);
      setError("Choose up to 20 files at a time.");
      return;
    }
    if (selected.some((file) => file.size > MAX_FILE_SIZE)) {
      setFiles([]);
      setError("Each file must be 1 GB or smaller.");
      return;
    }
    setFiles(selected);
  };

  const onFileChange = (event: ChangeEvent<HTMLInputElement>) => {
    if (event.target.files) chooseFiles(event.target.files);
  };

  const onDrop = (event: DragEvent<HTMLDivElement>) => {
    event.preventDefault();
    setDragging(false);
    chooseFiles(event.dataTransfer.files);
  };

  const clearSelection = () => {
    setFiles([]);
    if (inputRef.current) inputRef.current.value = "";
  };

  const onUpload = async () => {
    if (files.length === 0 || loading) {
      if (files.length === 0) setError("Choose at least one file to upload.");
      return;
    }
    if (password && password.length < 4) {
      setError("Use at least 4 characters for an upload password.");
      return;
    }

    setError("");
    setLoading(true);
    setProgress(0);
    setResult(null);
    setCopiedUrl("");
    const data = new FormData();
    files.forEach((file) => data.append("files", file));
    if (label.trim()) data.append("label", label.trim());
    if (password) data.append("password", password);

    try {
      const upload = await uploadFormData<UploadResult>("/upload", data, setProgress);
      setResult(upload);
      clearSelection();
      setLabel("");
      setPassword("");
    } catch (uploadError) {
      setError(uploadError instanceof Error && uploadError.message === "file_too_large"
        ? "Each file must be 1 GB or smaller."
        : "Upload failed. Check your connection and try again.");
    } finally {
      setLoading(false);
    }
  };

  const uploadAnother = () => {
    setResult(null);
    setProgress(0);
    setError("");
    setCopiedUrl("");
    clearSelection();
    inputRef.current?.click();
  };

  const logout = async () => {
    await apiFetch("/logout", { method: "POST" });
    window.location.assign("/");
  };

  const copyLink = async (url: string) => {
    try {
      await navigator.clipboard.writeText(url);
      setCopiedUrl(url);
    } catch {
      setError("Could not copy the link. Select it and copy it manually.");
    }
  };

  const selectedBytes = files.reduce((total, file) => total + file.size, 0);

  if (!me) {
    return (
      <div className="page auth">
        <div className="auth-card">
          <h1>{error ? "Dashboard unavailable" : "Loading your workspace..."}</h1>
          {error && <p className="error" role="alert">{error}</p>}
        </div>
      </div>
    );
  }

  return (
    <main className="page dashboard">
      <section className="dashboard-shell">
        <header className="dashboard-header dashboard-topbar">
          <Link className="dashboard-brand" to="/" aria-label="BabyShare home">
            <span className="dashboard-brand-mark">ϟ</span>
            <span>BabyShare</span>
          </Link>
          <div className="dashboard-actions">
            <Link className="btn btn-ghost" to="/files">File Vault</Link>
            {me.isAdmin && <Link className="btn btn-admin" to="/admin">Admin Panel</Link>}
            <button className="dashboard-logout" type="button" onClick={() => void logout()}>Log out</button>
          </div>
        </header>

        <section className="dashboard-welcome dashboard-card">
          <div>
            <p className="eyebrow">{me.isAdmin ? "Administrator workspace" : "Personal workspace"}</p>
            <h1>Good to see you, <span>{me.user}</span>.</h1>
            <p>Upload files, create secure links, and manage what you share from one focused workspace.</p>
          </div>
          <div className="dashboard-status" aria-label="Encryption status">
            <ShieldIcon />
            <div><span>Protection</span><strong>Encrypted at rest</strong></div>
          </div>
        </section>

        <div className="dashboard-grid dashboard-workspace-grid">
          <section className="dashboard-card upload-panel" aria-labelledby="new-share-heading">
            <div className="panel-head">
              <div>
                <p className="eyebrow">Secure upload</p>
                <h2 id="new-share-heading">Create a new share</h2>
              </div>
              <span className="pill">Up to 20 files</span>
            </div>

            <div
              className={`dashboard-dropzone${dragging ? " is-dragging" : ""}`}
              onDragEnter={(event) => { event.preventDefault(); setDragging(true); }}
              onDragOver={(event) => event.preventDefault()}
              onDragLeave={(event) => { if (event.currentTarget === event.target) setDragging(false); }}
              onDrop={onDrop}
            >
              <input ref={inputRef} className="dashboard-file-input" type="file" multiple onChange={onFileChange} />
              <span className="dashboard-upload-icon"><UploadIcon /></span>
              <h3>{files.length ? `${files.length} ${files.length === 1 ? "file" : "files"} selected` : "Drop files here"}</h3>
              <p>{files.length ? `${formatFileSize(selectedBytes)} ready to encrypt and share` : "or choose files from your device"}</p>
              <button className="btn btn-ghost dashboard-browse" type="button" onClick={() => inputRef.current?.click()} disabled={loading}>Browse files</button>
            </div>

            {files.length > 0 && (
              <div className="dashboard-file-list" aria-live="polite">
                {files.map((file) => (
                  <div className="dashboard-file" key={`${file.name}-${file.lastModified}`}>
                    <span><FileIcon /></span>
                    <div><strong>{file.name}</strong><small>{formatFileSize(file.size)}</small></div>
                  </div>
                ))}
                <button className="dashboard-text-button" type="button" onClick={clearSelection} disabled={loading}>Clear selection</button>
              </div>
            )}

            <form className="dashboard-upload-form" onSubmit={(event) => { event.preventDefault(); void onUpload(); }}>
              <div className="dashboard-options">
                <label>
                  Label <span>optional</span>
                  <input value={label} maxLength={120} onChange={(event) => setLabel(event.target.value)} placeholder="e.g. Project handoff" />
                </label>
                <label>
                  Link password <span>optional</span>
                  <input type="password" value={password} minLength={4} maxLength={128} onChange={(event) => setPassword(event.target.value)} placeholder="4+ characters" />
                </label>
              </div>

              <button type="submit" className="btn btn-guest dashboard-upload-button" disabled={loading || files.length === 0}>
                {loading ? `Encrypting and uploading ${progress}%` : "Create secure share"}
                {!loading && <ArrowIcon />}
              </button>
            </form>

            {loading && (
              <div className="upload-progress dashboard-progress" aria-live="polite">
                <progress max="100" value={progress} />
                <span>{progress}% complete</span>
              </div>
            )}
            {error && <p className="error dashboard-error" role="alert">{error}</p>}
          </section>

          <aside className="dashboard-card dashboard-side-panel">
            <div>
              <p className="eyebrow">Workspace tools</p>
              <h2>Everything in reach</h2>
            </div>
            <Link className="dashboard-tool" to="/files">
              <span className="dashboard-tool-icon"><FileIcon /></span>
              <span><strong>File Vault</strong><small>Review, download, or remove stored files.</small></span>
              <ArrowIcon />
            </Link>
            {me.isAdmin && (
              <Link className="dashboard-tool" to="/admin">
                <span className="dashboard-tool-icon admin"><ShieldIcon /></span>
                <span><strong>Admin controls</strong><small>Manage users and monitor shared files.</small></span>
                <ArrowIcon />
              </Link>
            )}
            <div className="dashboard-rule-list">
              <div><span>30 days</span><small>Signed-in links remain available.</small></div>
              <div><span>1 GB</span><small>Maximum size for every selected file.</small></div>
              <div><span>Private</span><small>Password protection is available per share.</small></div>
            </div>
          </aside>
        </div>

        {result && (
          <section className="dashboard-card share-results" aria-live="polite">
            <div className="panel-head">
              <div>
                <p className="eyebrow">Share created</p>
                <h2>{result.links.length === 1 ? "Your secure link is ready" : `${result.links.length} secure links are ready`}</h2>
              </div>
              <span className="pill alt">Ready to share</span>
            </div>
            <div className="share-grid">
              {result.links.map((link) => (
                <article key={link.url} className="share-row">
                  <div className="share-file-summary">
                    <span className="dashboard-tool-icon"><FileIcon /></span>
                    <div>
                      <strong>{link.name}</strong>
                      <div className="meta">{link.passwordRequired ? "Password protected" : "Anyone with the link can access"} · {expiryLabel(link.expires)}</div>
                    </div>
                  </div>
                  <div className="file-actions dashboard-share-actions">
                    <button className="btn btn-guest" type="button" onClick={() => void copyLink(link.url)}>{copiedUrl === link.url ? "Link copied" : "Copy link"}</button>
                    <a className="btn btn-register" href={`${link.url}?action=preview`}>Preview</a>
                    <a className="dashboard-inline-link" href={`${link.url}?action=download`}>Download</a>
                  </div>
                </article>
              ))}
            </div>
            <button className="dashboard-text-button dashboard-upload-another" type="button" onClick={uploadAnother}>Upload another file <ArrowIcon /></button>
          </section>
        )}
      </section>
    </main>
  );
}
