import { useEffect, useRef, useState } from "react";
import type { DragEvent } from "react";
import { apiFetch, apiUrl, uploadFormData } from "../lib/api";

type Account = { user: string; isAdmin: boolean };
type GuestUploadResult = {
  downloadPath?: string;
  expires: number;
  label: string;
  link: string;
  passwordRequired: boolean;
  previewPath?: string;
  qrCode: string;
  sharePath?: string;
};
type UserUploadLink = { expires: number; name: string; passwordRequired: boolean; qr: string; url: string };
type UserUploadResult = { links: UserUploadLink[] };

const MAX_FILE_SIZE = 1024 * 1024 * 1024;

function formatFileSize(bytes: number) {
  if (bytes < 1024) return `${bytes} B`;
  const units = ["KB", "MB", "GB"];
  const unitIndex = Math.min(Math.floor(Math.log(bytes) / Math.log(1024)) - 1, units.length - 1);
  const value = bytes / (1024 ** (unitIndex + 1));
  return `${value >= 10 ? value.toFixed(0) : value.toFixed(1)} ${units[unitIndex]}`;
}

function LightningMark() {
  return (
    <svg viewBox="0 0 24 24" aria-hidden="true">
      <path d="M13.2 1.8 4.6 13h6.1l-.9 9.2L19.4 11h-6.1l-.1-9.2Z" fill="currentColor" />
    </svg>
  );
}

function UploadArrow() {
  return (
    <svg viewBox="0 0 24 24" aria-hidden="true">
      <path d="M12 16V4m0 0L7.7 8.3M12 4l4.3 4.3M5 15.5v3A1.5 1.5 0 0 0 6.5 20h11a1.5 1.5 0 0 0 1.5-1.5v-3" fill="none" stroke="currentColor" strokeLinecap="round" strokeLinejoin="round" strokeWidth="1.7" />
    </svg>
  );
}

function ShieldIcon() {
  return <svg viewBox="0 0 24 24" aria-hidden="true"><path d="M12 3 5 6v5.3c0 4.4 3 7.9 7 9.7 4-1.8 7-5.3 7-9.7V6l-7-3Zm-3.2 9 2.1 2.1 4.4-4.4" fill="none" stroke="currentColor" strokeLinecap="round" strokeLinejoin="round" strokeWidth="1.7" /></svg>;
}

function SpeedIcon() {
  return <svg viewBox="0 0 24 24" aria-hidden="true"><path d="M4 14.5A8 8 0 1 1 20 14.5M12 12l3.6-3.6M12 17.5h.01" fill="none" stroke="currentColor" strokeLinecap="round" strokeLinejoin="round" strokeWidth="1.7" /></svg>;
}

function ClockIcon() {
  return <svg viewBox="0 0 24 24" aria-hidden="true"><circle cx="12" cy="12" r="8" fill="none" stroke="currentColor" strokeWidth="1.7" /><path d="M12 7.5V12l3 1.8" fill="none" stroke="currentColor" strokeLinecap="round" strokeLinejoin="round" strokeWidth="1.7" /></svg>;
}

function localGuestPath(result: GuestUploadResult, action: "share" | "preview" | "download") {
  const suppliedPath = action === "share"
    ? result.sharePath
    : action === "preview"
      ? result.previewPath
      : result.downloadPath;
  if (suppliedPath) return suppliedPath;

  try {
    const url = new URL(result.link);
    if (action === "share") return `${url.pathname}${url.search}`;
    const token = url.searchParams.get("token");
    if (token) return `/guest-download?token=${encodeURIComponent(token)}&action=${action}`;
  } catch {
    // Fall back to the original share URL below when an older response is malformed.
  }
  return result.link;
}

export default function Home() {
  const inputRef = useRef<HTMLInputElement>(null);
  const [account, setAccount] = useState<Account | null>(null);
  const [accountChecked, setAccountChecked] = useState(false);
  const [files, setFiles] = useState<File[]>([]);
  const [dragging, setDragging] = useState(false);
  const [loading, setLoading] = useState(false);
  const [progress, setProgress] = useState(0);
  const [error, setError] = useState("");
  const [guestResult, setGuestResult] = useState<GuestUploadResult | null>(null);
  const [userResult, setUserResult] = useState<UserUploadResult | null>(null);

  useEffect(() => {
    apiFetch("/api/me")
      .then((response) => response.ok ? response.json() as Promise<Account> : null)
      .then((data) => setAccount(data))
      .catch(() => setAccount(null))
      .finally(() => setAccountChecked(true));
  }, []);

  const isSignedIn = Boolean(account);
  const guestSharePath = guestResult ? localGuestPath(guestResult, "share") : "";
  const guestPreviewPath = guestResult ? localGuestPath(guestResult, "preview") : "";
  const guestDownloadPath = guestResult ? localGuestPath(guestResult, "download") : "";

  const selectFiles = (nextFiles: FileList | File[]) => {
    const selected = Array.from(nextFiles);
    setError("");
    setGuestResult(null);
    setUserResult(null);

    if (!isSignedIn && selected.length > 1) {
      setFiles([selected[0]]);
      setError("Guest uploads accept one file at a time. Sign in to upload multiple files.");
      return;
    }
    if (selected.some((file) => file.size > MAX_FILE_SIZE)) {
      setFiles([]);
      setError("Each file must be 1 GB or smaller.");
      return;
    }
    setFiles(selected);
  };

  const onDrop = (event: DragEvent<HTMLDivElement>) => {
    event.preventDefault();
    setDragging(false);
    selectFiles(event.dataTransfer.files);
  };

  const onUpload = async () => {
    if (files.length === 0 || loading) {
      if (files.length === 0) setError("Choose at least one file to upload.");
      return;
    }

    setError("");
    setLoading(true);
    setProgress(0);
    setGuestResult(null);
    setUserResult(null);
    const payload = new FormData();
    if (isSignedIn) {
      files.forEach((file) => payload.append("files", file));
    } else {
      payload.append("file", files[0]);
    }

    try {
      if (isSignedIn) {
        setUserResult(await uploadFormData<UserUploadResult>("/upload", payload, setProgress));
      } else {
        setGuestResult(await uploadFormData<GuestUploadResult>("/guest-upload", payload, setProgress));
      }
      setFiles([]);
      if (inputRef.current) inputRef.current.value = "";
    } catch (uploadError) {
      const code = uploadError instanceof Error ? uploadError.message : "";
      setError(code === "file_too_large" ? "Each file must be 1 GB or smaller." : "Upload failed. Please try again.");
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="home-page">
      <header className="site-header">
        <a className="brand" href="/" aria-label="BabyShare home">
          <span className="brand-mark"><LightningMark /></span>
          <span>BabyShare</span>
        </a>
        <nav aria-label="Account navigation">
          {isSignedIn ? (
            <a className="nav-action" href="/dashboard">Open dashboard</a>
          ) : (
            <a className="nav-action" href="/login">Log in</a>
          )}
        </nav>
      </header>

      <main className="home-main">
        <section className="home-hero" aria-labelledby="home-title">
          <p className="hero-kicker">Private file sharing</p>
          <h1 id="home-title">Baby<span>Share</span></h1>
          <p className="home-tagline">Share files. Simply and securely.</p>
          <p className="home-subcopy">Fast, private file sharing across your network.</p>
        </section>

        <section className="upload-section" aria-label="File upload">
          <div
            className={`upload-dropzone${dragging ? " is-dragging" : ""}`}
            onDragEnter={(event) => { event.preventDefault(); setDragging(true); }}
            onDragOver={(event) => event.preventDefault()}
            onDragLeave={(event) => { if (event.currentTarget === event.target) setDragging(false); }}
            onDrop={onDrop}
          >
            <div className="upload-icon"><UploadArrow /></div>
            <h2>{files.length ? `${files.length} ${files.length === 1 ? "file" : "files"} ready` : "Drag and drop files here"}</h2>
            {files.length ? (
              <div className="upload-selection" aria-live="polite">
                {files.map((file) => (
                  <span className="upload-file" key={`${file.name}-${file.lastModified}`} title={`${file.name} (${formatFileSize(file.size)})`}>
                    <span className="upload-file-name">{file.name}</span>
                    <span className="upload-file-size">{formatFileSize(file.size)}</span>
                  </span>
                ))}
              </div>
            ) : <p>or click to browse</p>}
            <input
              ref={inputRef}
              className="visually-hidden"
              type="file"
              multiple={isSignedIn}
              onChange={(event) => event.target.files && selectFiles(event.target.files)}
              aria-label={isSignedIn ? "Choose files to upload" : "Choose a file to upload"}
            />
            <div className="upload-actions">
              <button className="browse-button" type="button" onClick={() => inputRef.current?.click()} disabled={loading}>Browse files</button>
              <button className="upload-button" type="button" onClick={onUpload} disabled={loading || !accountChecked || files.length === 0} aria-busy={loading}>
                {loading ? `Uploading ${progress}%` : "Upload Files"}
              </button>
            </div>
            <p className="upload-hint">{isSignedIn ? "Signed in — upload up to 20 files, 1 GB each." : "Guest upload — one file up to 1 GB."}</p>
          </div>

          {!isSignedIn && <p className="advanced-upload">Need a label or password? <a href="/guest-upload">Use advanced guest upload</a>.</p>}
          {!accountChecked && <p className="upload-hint" aria-live="polite">Checking your session…</p>}
          {loading && <div className="upload-progress home-progress" aria-live="polite"><progress max="100" value={progress} /><span>{progress}%</span></div>}
          {error && <p className="error home-error" role="alert">{error}</p>}

          {guestResult && (
            <div className="home-upload-result" aria-live="polite">
              <strong>File uploaded</strong>
              <span>Your file is ready to preview, download, or share.</span>
              <div className="guest-file-actions" aria-label="Uploaded file actions">
                <a href={apiUrl(guestSharePath)} target="_blank" rel="noreferrer">Open share</a>
                <a href={apiUrl(guestPreviewPath)} target="_blank" rel="noreferrer">Preview</a>
                <a className="primary-action" href={apiUrl(guestDownloadPath)} target="_blank" rel="noreferrer">Download</a>
              </div>
              <a className="link" href={guestResult.link} target="_blank" rel="noreferrer">Share link: {guestResult.link}</a>
            </div>
          )}
          {userResult && (
            <div className="home-upload-result" aria-live="polite">
              <strong>{userResult.links.length} {userResult.links.length === 1 ? "share link" : "share links"} ready</strong>
              <a className="link" href="/dashboard">Open your dashboard to manage files and copy links.</a>
            </div>
          )}
        </section>

        <section className="feature-indicators" aria-label="BabyShare features">
          <article>
            <span className="indicator-icon private"><ShieldIcon /></span>
            <div><h2>Private Sharing</h2><p>Your files stay on your network.</p></div>
          </article>
          <article>
            <span className="indicator-icon fast"><SpeedIcon /></span>
            <div><h2>Fast Transfers</h2><p>Quick and reliable.</p></div>
          </article>
          <article>
            <span className="indicator-icon expiry"><ClockIcon /></span>
            <div><h2>Expiring Links</h2><p>Control how long files last.</p></div>
          </article>
        </section>
      </main>

      <footer className="site-footer">Private sharing · Password protection available · Expiring links</footer>
    </div>
  );
}
