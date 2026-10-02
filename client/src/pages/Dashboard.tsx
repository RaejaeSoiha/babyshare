// Authenticated direct-transfer workspace. File bytes stay in the two browsers.
import { useEffect, useRef, useState } from "react";
import type { ChangeEvent, DragEvent } from "react";
import { Link, useLocation, useNavigate } from "react-router-dom";
import { useLanTransfers } from "../components/LanTransfers";
import LogoutButton from "../components/LogoutButton";
import { apiFetch } from "../lib/api";

type Me = { isAdmin: boolean; user: string };
const MAX_FILE_SIZE = 1024 * 1024 * 1024;

function formatFileSize(bytes: number) {
  if (bytes < 1024) return `${bytes} B`;
  const units = ["KB", "MB", "GB"];
  const index = Math.min(Math.floor(Math.log(bytes) / Math.log(1024)) - 1, units.length - 1);
  const value = bytes / (1024 ** (index + 1));
  return `${value >= 10 ? value.toFixed(0) : value.toFixed(1)} ${units[index]}`;
}

export default function Dashboard() {
  const location = useLocation();
  const navigate = useNavigate();
  const inputRef = useRef<HTMLInputElement>(null);
  const { devices, error: lanError, requestTransfers, transfers } = useLanTransfers();
  const [me, setMe] = useState<Me | null>(null);
  const [files, setFiles] = useState<File[]>([]);
  const [recipientId, setRecipientId] = useState("");
  const [dragging, setDragging] = useState(false);
  const [sending, setSending] = useState(false);
  const [error, setError] = useState("");

  useEffect(() => {
    apiFetch("/api/me").then(async (response) => {
      if (response.status === 401) { window.location.assign("/login"); return; }
      if (!response.ok) throw new Error("account_load_failed");
      setMe(await response.json() as Me);
    }).catch(() => setError("Unable to load your account. Refresh the page and try again."));
  }, []);

  useEffect(() => {
    const pendingFiles = (location.state as { pendingFiles?: unknown } | null)?.pendingFiles;
    if (!Array.isArray(pendingFiles) || !pendingFiles.every((file) => file instanceof File)) return;
    setFiles(pendingFiles.slice(0, 20));
    navigate("/dashboard", { replace: true, state: null });
  }, [location.state, navigate]);

  useEffect(() => {
    if (!recipientId && devices[0]) setRecipientId(devices[0].id);
    if (recipientId && !devices.some((device) => device.id === recipientId)) setRecipientId(devices[0]?.id || "");
  }, [devices, recipientId]);

  const chooseFiles = (selected: FileList | File[]) => {
    const next = Array.from(selected);
    setError("");
    if (!next.length) return;
    if (next.length > 20) return setError("Choose up to 20 files at a time.");
    if (next.some((file) => file.size > MAX_FILE_SIZE)) return setError("Each file must be 1 GB or smaller.");
    setFiles(next);
  };

  const send = async () => {
    if (!files.length) return setError("Choose at least one file first.");
    if (!recipientId) return setError("Choose an online recipient. They must keep BabyShare open to accept.");
    setSending(true);
    setError("");
    try {
      await requestTransfers(recipientId, files);
      setFiles([]);
      if (inputRef.current) inputRef.current.value = "";
    } catch {
      setError("The file request could not be sent. Keep both devices online and try again.");
    } finally {
      setSending(false);
    }
  };

  if (!me) return <main className="page auth"><section className="auth-card"><h1>{error ? "Workspace unavailable" : "Loading your workspace…"}</h1>{error && <p className="error">{error}</p>}</section></main>;

  const activeTransfers = transfers.filter((transfer) => ["pending", "accepted", "receiving"].includes(transfer.status)).slice(0, 5);
  return (
    <main className="page dashboard direct-dashboard">
      <section className="dashboard-shell">
        <header className="dashboard-header dashboard-topbar">
          <Link className="dashboard-brand" to="/" aria-label="BabyShare home"><span className="dashboard-brand-mark">ϟ</span><span>BabyShare</span></Link>
          <div className="dashboard-actions"><Link className="btn btn-ghost" to="/files">Transfer history</Link><Link className="btn btn-ghost" to="/settings">Devices</Link>{me.isAdmin && <Link className="btn btn-admin" to="/admin">Admin</Link>}<LogoutButton /></div>
        </header>

        <section className="dashboard-welcome dashboard-card">
          <div><p className="eyebrow">Direct device transfer</p><h1>Hello, <span>{me.user}</span>.</h1><p>Select an online device, then send files directly through an encrypted browser-to-browser connection.</p></div>
          <div className="dashboard-status"><div aria-hidden="true">↔</div><div><span>Storage</span><strong>Never uploaded to BabyShare</strong></div></div>
        </section>

        <div className="dashboard-grid dashboard-workspace-grid direct-workspace-grid">
          <section className="dashboard-card upload-panel" aria-labelledby="send-direct-heading">
            <div className="panel-head"><div><p className="eyebrow">Send files</p><h2 id="send-direct-heading">Choose files and a recipient</h2></div><span className="pill">Up to 1 GB each</span></div>
            <div className={`dashboard-dropzone${dragging ? " is-dragging" : ""}`} onDragEnter={(event: DragEvent<HTMLDivElement>) => { event.preventDefault(); setDragging(true); }} onDragOver={(event) => event.preventDefault()} onDragLeave={(event) => { if (event.currentTarget === event.target) setDragging(false); }} onDrop={(event) => { event.preventDefault(); setDragging(false); chooseFiles(event.dataTransfer.files); }}>
              <input ref={inputRef} className="dashboard-file-input" type="file" multiple onChange={(event: ChangeEvent<HTMLInputElement>) => event.target.files && chooseFiles(event.target.files)} />
              <span className="dashboard-upload-icon" aria-hidden="true">↑</span><h3>{files.length ? `${files.length} file${files.length === 1 ? "" : "s"} selected` : "Drop files here"}</h3><p>{files.length ? files.map((file) => `${file.name} (${formatFileSize(file.size)})`).join(" · ") : "or choose files from your device"}</p>
              <button className="btn btn-ghost dashboard-browse" type="button" onClick={() => inputRef.current?.click()} disabled={sending}>Browse files</button>
            </div>
            <label className="direct-recipient-label">Online recipient
              <select value={recipientId} onChange={(event) => setRecipientId(event.target.value)} disabled={!devices.length || sending}>
                {!devices.length && <option value="">No other devices online</option>}
                {devices.map((device) => <option key={device.id} value={device.id}>{device.displayName} · {device.platform}</option>)}
              </select>
            </label>
            <div className="direct-send-actions"><button className="btn btn-register" type="button" disabled={!files.length || !recipientId || sending} onClick={() => void send()}>{sending ? "Sending request…" : "Request direct transfer"}</button>{files.length > 0 && <button className="dashboard-text-button" type="button" onClick={() => setFiles([])}>Clear files</button>}</div>
            <p className="nearby-privacy-note">The recipient chooses a save location before accepting. BabyShare transports only connection signals and transfer metadata.</p>
            {(error || lanError) && <p className="error" role="alert">{error || lanError}</p>}
          </section>

          <aside className="dashboard-card direct-status-card"><p className="eyebrow">Nearby devices</p><h2>{devices.length} online</h2><p>{devices.length ? "Only other active devices are listed. Your own device is never counted." : "Open BabyShare on another device and keep the page active."}</p><Link className="btn btn-ghost" to="/guest-upload">Pair a guest with QR</Link><div className="direct-transfer-summary"><strong>Active transfers</strong>{activeTransfers.length ? activeTransfers.map((transfer) => <p key={transfer.id}>{transfer.name} · {transfer.progress}% · {transfer.peerName}</p>) : <p>No transfers in progress.</p>}</div></aside>
        </div>
      </section>
    </main>
  );
}
