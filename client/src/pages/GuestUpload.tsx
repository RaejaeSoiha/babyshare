import { useRef, useState } from "react";
import type { FormEvent } from "react";
import { useLanTransfers } from "../components/LanTransfers";

const MAX_FILE_SIZE = 1024 * 1024 * 1024;

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
  const fileInputRef = useRef<HTMLInputElement>(null);
  const { devices, error: nearbyError, requestTransfers, transfers } = useLanTransfers();
  const [file, setFile] = useState<File | null>(null);
  const [recipientId, setRecipientId] = useState("");
  const [error, setError] = useState("");
  const [sending, setSending] = useState(false);
  const [requested, setRequested] = useState(false);

  const activeTransfer = transfers.find((transfer) => transfer.direction === "outgoing" && transfer.peerId === recipientId);

  const requestTransfer = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    setError("");
    if (!file) {
      setError("Choose one file to send.");
      return;
    }
    if (file.size > MAX_FILE_SIZE) {
      setError("The file must be 1 GB or smaller.");
      return;
    }
    if (!recipientId) {
      setError("Choose a nearby recipient first.");
      return;
    }
    setSending(true);
    try {
      await requestTransfers(recipientId, [file]);
      setRequested(true);
    } catch {
      setError("The recipient is no longer available. Keep both devices open and try again.");
    } finally {
      setSending(false);
    }
  };

  const startAnother = () => {
    setFile(null);
    setRecipientId("");
    setError("");
    setRequested(false);
    if (fileInputRef.current) fileInputRef.current.value = "";
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
        <section className="guest-upload-card" aria-labelledby="guest-upload-title">
          <div className="guest-upload-icon"><UploadIcon /></div>
          <p className="guest-upload-kicker">DIRECT GUEST TRANSFER</p>
          <h1 id="guest-upload-title">Send privately, without an upload.</h1>
          <p className="guest-upload-copy">Choose a nearby recipient. They must approve before the file moves directly between your browsers.</p>

          {!requested ? (
            <form className="guest-upload-form" onSubmit={requestTransfer}>
              <label className="guest-file-field">
                <span>Select file</span>
                <input ref={fileInputRef} type="file" required onChange={(event) => {
                  setFile(event.target.files?.[0] || null);
                  setError("");
                }} />
              </label>
              {file && <p className="guest-selected-file" aria-live="polite"><strong>{file.name}</strong><span>{formatFileSize(file.size)}</span></p>}
              <label>
                <span>Nearby recipient</span>
                <select value={recipientId} onChange={(event) => setRecipientId(event.target.value)} required>
                  <option value="">Choose a recipient</option>
                  {devices.map((device) => <option key={device.id} value={device.id}>{device.displayName} · {device.platform}</option>)}
                </select>
              </label>
              {devices.length === 0 && <p className="guest-upload-notes">No nearby recipients are online yet. Ask them to open BabyShare on the same network.</p>}
              <button type="submit" className="guest-upload-submit" disabled={sending || devices.length === 0}>
                {sending ? "Sending request…" : "Request direct transfer"}
              </button>
            </form>
          ) : (
            <div className="guest-success-card" aria-live="polite">
              <div className="guest-success-icon"><ShieldIcon /></div>
              <p className="guest-upload-kicker">TRANSFER REQUEST SENT</p>
              <h1>Waiting for approval.</h1>
              <p>Keep this page open. The file stays on your device until the recipient accepts.</p>
              {activeTransfer && <p className="guest-upload-notes">{activeTransfer.status === "pending" ? "Waiting for the recipient." : activeTransfer.status === "receiving" ? `Sending ${activeTransfer.progress}%` : "Direct connection is being prepared."}</p>}
              <button type="button" className="guest-upload-another" onClick={startAnother}>Send another file</button>
            </div>
          )}

          {(error || nearbyError) && <p className="guest-upload-error" role="alert">{error || nearbyError}</p>}
          <div className="guest-upload-notes" aria-label="Direct guest transfer details">
            <span>1 file · up to 1 GB</span>
            <span><ShieldIcon />Recipient approval required</span>
          </div>
        </section>
      </main>
    </div>
  );
}
