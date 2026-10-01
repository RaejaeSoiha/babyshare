import { useEffect, useRef, useState } from "react";
import type { DragEvent } from "react";
import { Link, useNavigate } from "react-router-dom";
import { useLanTransfers } from "../components/LanTransfers";
import { apiFetch } from "../lib/api";

type Account = { user: string };
const MAX_FILE_SIZE = 1024 * 1024 * 1024;

function formatFileSize(bytes: number) {
  if (bytes < 1024) return `${bytes} B`;
  const units = ["KB", "MB", "GB"];
  const index = Math.min(Math.floor(Math.log(bytes) / Math.log(1024)) - 1, units.length - 1);
  const value = bytes / (1024 ** (index + 1));
  return `${value >= 10 ? value.toFixed(0) : value.toFixed(1)} ${units[index]}`;
}

function LightningMark() {
  return <svg viewBox="0 0 24 24" aria-hidden="true"><path d="M13.2 1.8 4.6 13h6.1l-.9 9.2L19.4 11h-6.1l-.1-9.2Z" fill="currentColor" /></svg>;
}

function UploadArrow() {
  return <svg viewBox="0 0 24 24" aria-hidden="true"><path d="M12 16V4m0 0L7.7 8.3M12 4l4.3 4.3M5 15.5v3A1.5 1.5 0 0 0 6.5 20h11a1.5 1.5 0 0 0 1.5-1.5v-3" fill="none" stroke="currentColor" strokeLinecap="round" strokeLinejoin="round" strokeWidth="1.7" /></svg>;
}

function UsersIcon() {
  return <svg viewBox="0 0 24 24" aria-hidden="true"><path d="M16 19v-1.1c0-2-1.8-3.6-4-3.6s-4 1.6-4 3.6V19m11-1v-.7c0-1.5-1-2.8-2.5-3.3M7.5 14C6 14.5 5 15.8 5 17.3v.7M12 11.5a3 3 0 1 0 0-6 3 3 0 0 0 0 6Zm5-1.4a2.4 2.4 0 1 0 0-4.8M7 10.1a2.4 2.4 0 1 1 0-4.8" fill="none" stroke="currentColor" strokeLinecap="round" strokeLinejoin="round" strokeWidth="1.6" /></svg>;
}

function ChatIcon() {
  return <svg viewBox="0 0 24 24" aria-hidden="true"><path d="M6.3 17.6 3.8 20l.6-4.1A7.6 7.6 0 0 1 3 11.6C3 7.4 7 4 12 4s9 3.4 9 7.6-4 7.6-9 7.6c-1.1 0-2.2-.2-3.2-.5l-2.5-1.1Z" fill="none" stroke="currentColor" strokeLinecap="round" strokeLinejoin="round" strokeWidth="1.65" /><path d="M8.5 11.7h.01M12 11.7h.01M15.5 11.7h.01" fill="none" stroke="currentColor" strokeLinecap="round" strokeWidth="2.3" /></svg>;
}

function ShieldIcon() {
  return <svg viewBox="0 0 24 24" aria-hidden="true"><path d="M12 3 5 6v5.3c0 4.4 3 7.9 7 9.7 4-1.8 7-5.3 7-9.7V6l-7-3Zm-3.2 9 2.1 2.1 4.4-4.4" fill="none" stroke="currentColor" strokeLinecap="round" strokeLinejoin="round" strokeWidth="1.7" /></svg>;
}

function avatarInitial(name: string) {
  return name.trim().charAt(0).toUpperCase() || "G";
}

export default function Home() {
  const navigate = useNavigate();
  const inputRef = useRef<HTMLInputElement>(null);
  const [account, setAccount] = useState<Account | null>(null);
  const [accountChecked, setAccountChecked] = useState(false);
  const [files, setFiles] = useState<File[]>([]);
  const [dragging, setDragging] = useState(false);
  const [error, setError] = useState("");
  const [nearbyOpen, setNearbyOpen] = useState(false);
  const { devices, error: lanError } = useLanTransfers();

  useEffect(() => {
    let active = true;
    void apiFetch("/api/me")
      .then(async (response) => response.ok ? response.json() as Promise<Account> : null)
      .then((value) => { if (active) setAccount(value); })
      .catch(() => { if (active) setAccount(null); })
      .finally(() => { if (active) setAccountChecked(true); });
    return () => { active = false; };
  }, []);

  const signedIn = Boolean(account);
  const chooseFiles = (selected: FileList | File[]) => {
    const next = Array.from(selected);
    setError("");
    if (!next.length) return;
    if (next.length > 20) return setError("Choose up to 20 files at a time.");
    if (next.some((file) => file.size > MAX_FILE_SIZE)) return setError("Each file must be 1 GB or smaller.");
    setFiles(next);
  };

  const dropFiles = (event: DragEvent<HTMLDivElement>) => {
    event.preventDefault();
    setDragging(false);
    chooseFiles(event.dataTransfer.files);
  };

  const continueToTransfer = () => {
    if (!files.length) return setError("Choose at least one file first.");
    if (!signedIn) {
      navigate("/guest-upload");
      return;
    }
    navigate("/dashboard", { state: { pendingFiles: files } });
  };

  return (
    <div className="home-page">
      <header className="site-header">
        <Link className="brand" to="/" aria-label="BabyShare home">
          <span className="brand-mark"><LightningMark /></span><span>BabyShare</span>
        </Link>
        <nav className="home-nav" aria-label="Account navigation">
          {signedIn ? <Link className="nav-action" to="/dashboard">Workspace</Link> : <Link className="nav-action" to="/login">Log in</Link>}
        </nav>
      </header>

      <main className="home-main">
        <section className="home-hero" aria-labelledby="home-title"><h1 id="home-title">Baby<span>Share</span></h1></section>
        <section className="feature-indicators" aria-label="BabyShare features">
          <article title="Private sharing"><span className="indicator-icon private"><ShieldIcon /></span><h2>Private sharing</h2></article>
          <article title="Nearby colleagues"><span className="indicator-icon fast"><UsersIcon /></span><h2>Nearby colleagues</h2></article>
          <article title="Ephemeral chat"><span className="indicator-icon expiry"><ChatIcon /></span><h2>Ephemeral chat</h2></article>
        </section>

        <section className="upload-section" aria-label="Direct file transfer">
          <div className="home-action-grid">
            <section className="upload-share-card" aria-labelledby="upload-share-title">
              <div className="action-card-heading"><span className="action-card-icon"><UploadArrow /></span><div><h2 id="upload-share-title">Share a file</h2></div></div>
              <div className={`upload-dropzone${dragging ? " is-dragging" : ""}`} onDragEnter={(event) => { event.preventDefault(); setDragging(true); }} onDragOver={(event) => event.preventDefault()} onDragLeave={(event) => { if (event.currentTarget === event.target) setDragging(false); }} onDrop={dropFiles}>
                <div className="upload-icon"><UploadArrow /></div>
                <h2>{files.length ? `${files.length} ${files.length === 1 ? "file" : "files"} ready` : "Drag and drop files here"}</h2>
                {files.length ? <div className="upload-selection" aria-live="polite">{files.map((file) => <span className="upload-file" key={`${file.name}-${file.lastModified}`}><span className="upload-file-name">{file.name}</span><span className="upload-file-size">{formatFileSize(file.size)}</span></span>)}</div> : <p>or click to browse</p>}
                <input ref={inputRef} className="visually-hidden" type="file" multiple onChange={(event) => event.target.files && chooseFiles(event.target.files)} aria-label="Choose files to transfer" />
                <div className="upload-actions">
                  <button className="browse-button" type="button" onClick={() => inputRef.current?.click()}>Choose files</button>
                  <button className="upload-button" type="button" onClick={continueToTransfer} disabled={!accountChecked || !files.length}>{signedIn ? "Start direct transfer" : "Continue with QR pairing"}</button>
                </div>
                <p className="upload-hint">Files move directly between browsers. BabyShare does not store a copy.</p>
              </div>
              {!signedIn && <p className="advanced-upload">Want to share without an account? <Link to="/guest-upload">Use QR pairing</Link>.</p>}
              {error && <p className="error home-error" role="alert">{error}</p>}
            </section>
          </div>
        </section>
      </main>

      {nearbyOpen ? (
        <aside className="nearby-users-panel" aria-label="Nearby users">
          <header className="nearby-users-panel-header"><div className="nearby-users-panel-title"><span className="nearby-users-panel-icon"><UsersIcon /></span><div><p className="nearby-kicker">Company LAN · private</p><div className="nearby-users-panel-heading-row"><h2>Nearby Users</h2><span className="nearby-online-count"><i aria-hidden="true" />{devices.length} online</span></div></div></div><button type="button" className="nearby-users-panel-toggle" onClick={() => setNearbyOpen(false)} aria-label="Minimize Nearby Users">−</button></header>
          {lanError && <p className="error nearby-panel-error" role="alert">{lanError}</p>}
          <div className="nearby-users-panel-list" aria-live="polite">
            {devices.length === 0 ? <p className="nearby-empty">No colleagues are online yet. Ask a teammate to open BabyShare on this network.</p> : devices.map((device) => <article className="nearby-panel-user" key={device.id}><button type="button" className="nearby-panel-user-select" onClick={() => navigate(signedIn ? "/dashboard" : "/login")}><span className="nearby-user-avatar" aria-hidden="true"><i />{avatarInitial(device.displayName)}</span><span className="nearby-device-details"><strong>{device.displayName}</strong><small>{device.deviceName}</small></span><span className="nearby-device-online"><span aria-hidden="true" />Online</span><span className="nearby-panel-user-arrow" aria-hidden="true">›</span></button></article>)}
          </div>
          <p className="nearby-privacy-note">Open your workspace to chat and send files.</p>
        </aside>
      ) : (
        <button type="button" className="nearby-users-tab" onClick={() => setNearbyOpen(true)} aria-label={`Open Nearby Users: ${devices.length} other users online`}><UsersIcon /><span>Nearby Users</span><span className="nearby-online-count"><i aria-hidden="true" />{devices.length}</span></button>
      )}
      <footer className="site-footer">Encrypted sharing · Recipient-approved transfers · Ephemeral chat</footer>
    </div>
  );
}
