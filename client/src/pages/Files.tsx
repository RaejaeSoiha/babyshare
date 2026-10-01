// Metadata-only transfer history. No entry provides a server-side download.
import { Link } from "react-router-dom";
import { useLanTransfers } from "../components/LanTransfers";

function formatFileSize(bytes: number) {
  if (bytes < 1024) return `${bytes} B`;
  const units = ["KB", "MB", "GB"];
  const index = Math.min(Math.floor(Math.log(bytes) / Math.log(1024)) - 1, units.length - 1);
  return `${(bytes / (1024 ** (index + 1))).toFixed(1)} ${units[index]}`;
}

function statusLabel(status: string) {
  if (status === "completed") return "Completed";
  if (status === "receiving") return "In progress";
  if (status === "accepted") return "Connecting";
  if (status === "pending") return "Waiting for approval";
  if (status === "cancelled") return "Cancelled";
  return "Failed";
}

export default function Files() {
  const { transfers } = useLanTransfers();
  return (
    <main className="page vault-page transfer-history-page">
      <section className="vault-shell">
        <header className="dashboard-header dashboard-topbar vault-topbar">
          <Link className="dashboard-brand" to="/" aria-label="BabyShare home"><span className="dashboard-brand-mark">ϟ</span><span>BabyShare</span></Link>
          <div className="dashboard-actions"><Link className="btn btn-ghost" to="/dashboard">Send files</Link></div>
        </header>
        <section className="vault-hero"><div><p className="eyebrow">Private metadata</p><h1>Transfer history</h1><p>BabyShare records transfer names, sizes, dates, peers, and status for this active workspace. It never stores a downloadable server copy.</p></div><span className="vault-count">{transfers.length} {transfers.length === 1 ? "transfer" : "transfers"}</span></section>
        <section className="vault-card transfer-history-list" aria-label="Direct transfer history">
          {transfers.length === 0 ? <div className="vault-empty"><h2>No transfers yet</h2><p>Start a direct transfer from your workspace or pair a guest device with QR.</p><Link className="btn btn-register" to="/dashboard">Send a file</Link></div> : transfers.map((transfer) => (
            <article className="vault-file" key={transfer.id}>
              <div className="vault-file-icon" aria-hidden="true">↔</div>
              <div className="vault-file-details"><div className="vault-file-title-row"><strong>{transfer.relativePath || transfer.name}</strong><span className="vault-protection">Direct only</span></div><div className="vault-file-meta"><span>{transfer.direction === "outgoing" ? `Sent to ${transfer.peerName}` : `Received from ${transfer.peerName}`}</span><span>{formatFileSize(transfer.size)}</span><span>{new Date(transfer.updatedAt).toLocaleString()}</span></div></div>
              <div className={`transfer-history-status status-${transfer.status}`}><strong>{statusLabel(transfer.status)}</strong><span>{transfer.progress}%</span></div>
            </article>
          ))}
        </section>
      </section>
    </main>
  );
}
