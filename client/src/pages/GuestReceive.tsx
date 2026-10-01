import { useCallback, useEffect, useRef, useState } from "react";
import { useSearchParams } from "react-router-dom";
import {
  acceptQrPairing,
  claimQrPairing,
  completeQrPairing,
  QR_PEER_CONFIG,
  readQrPairing,
  resolveQrPairingCode,
  sendQrSignal,
  takeQrSignals,
} from "../lib/qrPairing";
import type { QrCredentials, QrPairing, QrSignal } from "../lib/qrPairing";

type ReceivedFile = {
  name: string;
  size: number;
  type: string;
  url?: string;
};

const MEMORY_RECEIVE_LIMIT = 32 * 1024 * 1024;

function LightningMark() {
  return <svg viewBox="0 0 24 24" aria-hidden="true"><path d="M13.2 1.8 4.6 13h6.1l-.9 9.2L19.4 11h-6.1l-.1-9.2Z" fill="currentColor" /></svg>;
}

function ShieldIcon() {
  return <svg viewBox="0 0 24 24" aria-hidden="true"><path d="M12 3 5 6v5.3c0 4.4 3 7.9 7 9.7 4-1.8 7-5.3 7-9.7V6l-7-3Zm-3.2 9 2.1 2.1 4.4-4.4" fill="none" stroke="currentColor" strokeLinecap="round" strokeLinejoin="round" strokeWidth="1.7" /></svg>;
}

function formatFileSize(bytes: number) {
  if (bytes < 1024 * 1024) return `${Math.max(1, Math.round(bytes / 1024))} KB`;
  if (bytes < 1024 * 1024 * 1024) return `${(bytes / (1024 * 1024)).toFixed(bytes >= 100 * 1024 * 1024 ? 0 : 1)} MB`;
  return `${(bytes / (1024 * 1024 * 1024)).toFixed(1)} GB`;
}

function pairingError(error: unknown) {
  if (error instanceof Error && error.message === "pairing_taken") return "This QR code has already been opened on another device.";
  if (error instanceof Error && error.message === "pairing_expired") return "This QR code expired. Ask the sender to create a new one.";
  return "This direct transfer is unavailable. Ask the sender to create a new QR code.";
}

export default function GuestReceive() {
  const [searchParams] = useSearchParams();
  const queryPairToken = (searchParams.get("pair") || "").toLowerCase();
  const [pairToken, setPairToken] = useState(/^[a-f0-9]{32}$/u.test(queryPairToken) ? queryPairToken : "");
  const [manualCode, setManualCode] = useState((searchParams.get("code") || "").replace(/\D/g, "").slice(0, 8));
  const hasValidPairToken = /^[a-f0-9]{32}$/u.test(pairToken);
  const pcRef = useRef<RTCPeerConnection | null>(null);
  const pendingCandidatesRef = useRef<RTCIceCandidateInit[]>([]);
  const chunksRef = useRef<ArrayBuffer[]>([]);
  const writerRef = useRef<FileSystemWritableFileStream | null>(null);
  const writeChainRef = useRef<Promise<void>>(Promise.resolve());
  const mimeTypeRef = useRef("application/octet-stream");
  const receivedBytesRef = useRef(0);
  const claimPromiseRef = useRef<Promise<{ pairing: QrPairing; receiverSecret: string }> | null>(null);
  const [pairing, setPairing] = useState<QrPairing | null>(null);
  const [credentials, setCredentials] = useState<QrCredentials | null>(null);
  const [accepting, setAccepting] = useState(false);
  const [connecting, setConnecting] = useState(false);
  const [progress, setProgress] = useState(0);
  const [received, setReceived] = useState<ReceivedFile | null>(null);
  const [error, setError] = useState("");
  const displayedError = error;

  const closeConnection = useCallback(() => {
    pcRef.current?.close();
    pcRef.current = null;
    pendingCandidatesRef.current = [];
  }, []);

  useEffect(() => {
    if (!hasValidPairToken) return undefined;
    const key = `babyshare.qr.receiver.${pairToken}`;
    const storedSecret = window.sessionStorage.getItem(key) || undefined;
    if (!claimPromiseRef.current) claimPromiseRef.current = claimQrPairing(pairToken, storedSecret);
    let active = true;
    void claimPromiseRef.current.then((claimed) => {
      if (!active) return;
      window.sessionStorage.setItem(key, claimed.receiverSecret);
      setCredentials({ pairToken, role: "receiver", secret: claimed.receiverSecret });
      setPairing(claimed.pairing);
    }).catch((cause) => { if (active) setError(pairingError(cause)); });
    return () => { active = false; };
  }, [hasValidPairToken, pairToken]);

  useEffect(() => {
    if (!credentials || received) return undefined;
    let active = true;
    const refresh = async () => {
      try {
        const next = await readQrPairing(credentials);
        if (active) setPairing(next.pairing);
      } catch (cause) {
        if (active) setError(pairingError(cause));
      }
    };
    void refresh();
    const interval = window.setInterval(refresh, 900);
    return () => { active = false; window.clearInterval(interval); };
  }, [credentials, received]);

  const handleDataChannel = useCallback((channel: RTCDataChannel, activeCredentials: QrCredentials) => {
    channel.binaryType = "arraybuffer";
    channel.onmessage = (event) => {
      if (typeof event.data === "string") {
        let control: { mimeType?: string; name?: string; size?: number; type?: string } = {};
        try { control = JSON.parse(event.data) as typeof control; } catch { return; }
        if (control.type === "metadata") {
          mimeTypeRef.current = control.mimeType || "application/octet-stream";
          return;
        }
        if (control.type !== "complete" || !pairing || receivedBytesRef.current !== pairing.file.size) {
          setError("The received file was incomplete. Ask the sender to try again.");
          return;
        }
        void writeChainRef.current.then(async () => {
          await writerRef.current?.close();
          const receivedFile = writerRef.current ? null : new Blob(chunksRef.current, { type: mimeTypeRef.current });
          const url = receivedFile ? URL.createObjectURL(receivedFile) : undefined;
          setReceived({ name: pairing.file.name, size: pairing.file.size, type: receivedFile?.type || mimeTypeRef.current, url });
          setProgress(100);
          setConnecting(false);
          void completeQrPairing(activeCredentials).catch(() => {});
        }).catch(() => setError("The received file could not be saved. Ask the sender to try again."));
        return;
      }
      const chunk = event.data instanceof ArrayBuffer ? event.data : null;
      if (!chunk || !pairing) return;
      if (receivedBytesRef.current + chunk.byteLength > pairing.file.size) {
        setError("The sender sent more data than expected, so the transfer was stopped.");
        closeConnection();
        return;
      }
      writeChainRef.current = writeChainRef.current.then(async () => {
        if (writerRef.current) await writerRef.current.write(chunk);
        else chunksRef.current.push(chunk);
      });
      receivedBytesRef.current += chunk.byteLength;
      setProgress(Math.min(99, Math.round((receivedBytesRef.current / pairing.file.size) * 100)));
    };
  }, [closeConnection, pairing]);

  const receiveOffer = useCallback(async (signal: QrSignal, activeCredentials: QrCredentials) => {
    if (!signal.description || pcRef.current) return;
    const pc = new RTCPeerConnection(QR_PEER_CONFIG);
    pcRef.current = pc;
    pc.onicecandidate = (event) => {
      if (event.candidate) void sendQrSignal(activeCredentials, { candidate: event.candidate.toJSON(), sessionId: signal.sessionId, type: "candidate" }).catch(() => setError(pairingError(null)));
    };
    pc.onconnectionstatechange = () => {
      if (["failed", "closed"].includes(pc.connectionState) && !received) setError(pairingError(null));
    };
    pc.ondatachannel = (event) => handleDataChannel(event.channel, activeCredentials);
    await pc.setRemoteDescription(signal.description);
    const queued = pendingCandidatesRef.current;
    pendingCandidatesRef.current = [];
    await Promise.all(queued.map((candidate) => pc.addIceCandidate(candidate)));
    await pc.setLocalDescription(await pc.createAnswer());
    await sendQrSignal(activeCredentials, { description: pc.localDescription?.toJSON(), sessionId: signal.sessionId, type: "answer" });
  }, [handleDataChannel, received]);

  const handleSignal = useCallback(async (signal: QrSignal, activeCredentials: QrCredentials) => {
    if (signal.type === "offer") {
      await receiveOffer(signal, activeCredentials);
    } else if (signal.type === "candidate" && signal.candidate) {
      const pc = pcRef.current;
      if (pc?.remoteDescription) await pc.addIceCandidate(signal.candidate);
      else pendingCandidatesRef.current.push(signal.candidate);
    } else if (signal.type === "hangup") {
      closeConnection();
      setError("The sender cancelled the direct transfer.");
    }
  }, [closeConnection, receiveOffer]);

  useEffect(() => {
    if (!credentials || pairing?.status !== "accepted" || received) return undefined;
    let active = true;
    const poll = async () => {
      try {
        const { signals } = await takeQrSignals(credentials);
        for (const signal of signals) await handleSignal(signal, credentials);
      } catch (cause) {
        if (active) setError(pairingError(cause));
      }
    };
    void poll();
    const interval = window.setInterval(poll, 650);
    return () => { active = false; window.clearInterval(interval); };
  }, [credentials, handleSignal, pairing?.status, received]);

  useEffect(() => () => {
    closeConnection();
    if (received?.url) URL.revokeObjectURL(received.url);
  }, [closeConnection, received]);

  const accept = async () => {
    if (!credentials || !pairing) return;
    setAccepting(true);
    setError("");
    chunksRef.current = [];
    writerRef.current = null;
    writeChainRef.current = Promise.resolve();
    receivedBytesRef.current = 0;
    mimeTypeRef.current = "application/octet-stream";
    try {
      if (window.showSaveFilePicker) {
        const handle = await window.showSaveFilePicker({ suggestedName: pairing.file.name });
        writerRef.current = await handle.createWritable();
      } else if (pairing.file.size > MEMORY_RECEIVE_LIMIT) {
        throw new Error("save_picker_required");
      }
      const result = await acceptQrPairing(credentials);
      setPairing(result.pairing);
      setConnecting(true);
    } catch (cause) {
      setError(cause instanceof Error && cause.message === "save_picker_required"
        ? "This browser needs its save-file picker for transfers larger than 32 MB. Use a current desktop browser or ask the sender to choose a smaller file."
        : pairingError(cause));
    } finally {
      setAccepting(false);
    }
  };

  const previewable = received && /^(image|audio|video)\//u.test(received.type) || received?.type === "application/pdf";

  const submitManualCode = async () => {
    if (!/^\d{8}$/u.test(manualCode)) return setError("Enter the 8-digit code shown by the sender.");
    setError("");
    try {
      const resolved = await resolveQrPairingCode(manualCode);
      claimPromiseRef.current = null;
      setPairToken(resolved.pairToken);
    } catch (cause) {
      setError(pairingError(cause));
    }
  };

  return (
    <div className="page guest-upload-page">
      <header className="guest-upload-header">
        <a className="guest-upload-brand" href="/" aria-label="BabyShare home"><span className="guest-upload-brand-mark"><LightningMark /></span><span>BabyShare</span></a>
        <a className="guest-upload-home-link" href="/">Back to home</a>
      </header>
      <main className="guest-upload-shell">
        <section className="guest-upload-card" aria-labelledby="guest-receive-title">
          <div className="guest-upload-icon"><ShieldIcon /></div>
          <p className="guest-upload-kicker">DIRECT FILE TRANSFER</p>
          <h1 id="guest-receive-title">{received ? "Your file is ready." : hasValidPairToken ? "A file is waiting for you." : "Enter a pairing code."}</h1>
          {!hasValidPairToken && !received && <form className="guest-upload-form" onSubmit={(event) => { event.preventDefault(); void submitManualCode(); }}><label className="guest-file-field"><span>8-digit pairing code</span><input inputMode="numeric" autoComplete="one-time-code" value={manualCode} maxLength={8} onChange={(event) => setManualCode(event.target.value.replace(/\D/g, "").slice(0, 8))} placeholder="12345678" /></label><button type="submit" className="guest-upload-submit">Connect</button></form>}
          {pairing && !received && <p className="guest-upload-copy"><strong>{pairing.file.name}</strong><br />{formatFileSize(pairing.file.size)} · The sender keeps the file on their device until you approve.</p>}
          {!pairing && !displayedError && <p className="guest-upload-copy">Opening the secure direct transfer…</p>}

          {pairing && !received && pairing.status !== "accepted" && (
            <button type="button" className="guest-upload-submit" disabled={accepting} onClick={() => void accept()}>{accepting ? "Connecting…" : "Review and accept file"}</button>
          )}
          {pairing?.status === "accepted" && !received && <>
            <p className="guest-upload-copy">{connecting ? "Connecting to the sender. Keep this page open." : "Waiting for the sender to start the direct transfer."}</p>
            {progress > 0 && <div className="guest-upload-progress"><progress value={progress} max="100" /><span>{progress}%</span></div>}
          </>}
          {received && <div className="guest-success-card guest-received-file">
            <div className="guest-success-icon"><ShieldIcon /></div>
            <p className="guest-upload-kicker">DIRECT TRANSFER COMPLETE</p>
            <h1>{received.name}</h1>
            <p>{formatFileSize(received.size)} {received.url ? "received directly in this browser." : "was saved directly to your device."}</p>
            <div className="guest-success-actions">
               {previewable && received.url && <a href={received.url} target="_blank" rel="noreferrer">Preview file</a>}
               {received.url && <a href={received.url} download={received.name}>Download file</a>}
            </div>
          </div>}
          {displayedError && <p className="guest-upload-error" role="alert">{displayedError}</p>}
          <div className="guest-upload-notes"><span><ShieldIcon />No file is stored on BabyShare</span><span>QR codes expire after 10 minutes</span></div>
        </section>
      </main>
    </div>
  );
}
