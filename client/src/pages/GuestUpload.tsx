import { useCallback, useEffect, useRef, useState } from "react";
import type { FormEvent } from "react";
import QRCode from "qrcode";
import {
  completeQrPairing,
  createQrPairing,
  QR_PEER_CONFIG,
  readQrPairing,
  sendQrSignal,
  takeQrSignals,
} from "../lib/qrPairing";
import type { QrCredentials, QrPairing, QrSignal } from "../lib/qrPairing";

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
  if (bytes < MAX_FILE_SIZE) return `${(bytes / (1024 * 1024)).toFixed(bytes >= 100 * 1024 * 1024 ? 0 : 1)} MB`;
  return `${(bytes / MAX_FILE_SIZE).toFixed(1)} GB`;
}

function directTransferError(error: unknown) {
  if (error instanceof Error && error.message === "pairing_expired") return "This QR code expired. Choose the file again to make a new one.";
  return "The direct connection could not be completed. Keep both pages open and try a new QR code.";
}

export default function GuestUpload() {
  const fileInputRef = useRef<HTMLInputElement>(null);
  const pcRef = useRef<RTCPeerConnection | null>(null);
  const pendingCandidatesRef = useRef<RTCIceCandidateInit[]>([]);
  const startedRef = useRef(false);
  const [file, setFile] = useState<File | null>(null);
  const [pairing, setPairing] = useState<QrPairing | null>(null);
  const [credentials, setCredentials] = useState<QrCredentials | null>(null);
  const [qrImage, setQrImage] = useState("");
  const [creating, setCreating] = useState(false);
  const [transferState, setTransferState] = useState<"waiting" | "connecting" | "sending" | "complete">("waiting");
  const [progress, setProgress] = useState(0);
  const [error, setError] = useState("");

  const closeConnection = useCallback(() => {
    pcRef.current?.close();
    pcRef.current = null;
    pendingCandidatesRef.current = [];
  }, []);

  const sendFile = useCallback(async (channel: RTCDataChannel, transferFile: File, activeCredentials: QrCredentials) => {
    channel.send(JSON.stringify({ mimeType: transferFile.type || "application/octet-stream", name: transferFile.name, size: transferFile.size, type: "metadata" }));
    const chunkSize = 64 * 1024;
    for (let offset = 0; offset < transferFile.size; offset += chunkSize) {
      while (channel.bufferedAmount > 512 * 1024) {
        await new Promise<void>((resolve) => {
          const timeout = window.setTimeout(resolve, 250);
          channel.addEventListener("bufferedamountlow", () => {
            window.clearTimeout(timeout);
            resolve();
          }, { once: true });
        });
      }
      if (channel.readyState !== "open") throw new Error("channel_closed");
      channel.send(await transferFile.slice(offset, Math.min(offset + chunkSize, transferFile.size)).arrayBuffer());
      setProgress(Math.min(100, Math.floor(((offset + chunkSize) / transferFile.size) * 100)));
    }
    channel.send(JSON.stringify({ type: "complete" }));
    await completeQrPairing(activeCredentials);
    setProgress(100);
    setTransferState("complete");
  }, []);

  const beginDirectTransfer = useCallback(async () => {
    if (!credentials || !file || startedRef.current || typeof RTCPeerConnection === "undefined") return;
    startedRef.current = true;
    setTransferState("connecting");
    const sessionId = `qr_${credentials.pairToken}`;
    const pc = new RTCPeerConnection(QR_PEER_CONFIG);
    pcRef.current = pc;
    const channel = pc.createDataChannel("babyshare-qr-file", { ordered: true });
    channel.bufferedAmountLowThreshold = 256 * 1024;
    pc.onicecandidate = (event) => {
      if (event.candidate) void sendQrSignal(credentials, { candidate: event.candidate.toJSON(), sessionId, type: "candidate" }).catch(() => setError(directTransferError(null)));
    };
    pc.onconnectionstatechange = () => {
      if (["failed", "closed"].includes(pc.connectionState)) setError(directTransferError(null));
    };
    channel.onopen = () => {
      setTransferState("sending");
      void sendFile(channel, file, credentials).catch((cause) => setError(directTransferError(cause)));
    };
    try {
      await pc.setLocalDescription(await pc.createOffer());
      await sendQrSignal(credentials, { description: pc.localDescription?.toJSON(), sessionId, type: "offer" });
    } catch (cause) {
      setError(directTransferError(cause));
    }
  }, [credentials, file, sendFile]);

  const handleSignal = useCallback(async (signal: QrSignal) => {
    const pc = pcRef.current;
    if (!pc) return;
    if (signal.type === "answer" && signal.description) {
      await pc.setRemoteDescription(signal.description);
      const queued = pendingCandidatesRef.current;
      pendingCandidatesRef.current = [];
      await Promise.all(queued.map((candidate) => pc.addIceCandidate(candidate)));
    } else if (signal.type === "candidate" && signal.candidate) {
      if (pc.remoteDescription) await pc.addIceCandidate(signal.candidate);
      else pendingCandidatesRef.current.push(signal.candidate);
    } else if (signal.type === "hangup") {
      closeConnection();
      setError("The recipient cancelled the direct transfer.");
    }
  }, [closeConnection]);

  useEffect(() => {
    if (!credentials) return undefined;
    let active = true;
    const refresh = async () => {
      try {
        const next = await readQrPairing(credentials);
        if (active) setPairing(next.pairing);
      } catch (cause) {
        if (active) setError(directTransferError(cause));
      }
    };
    void refresh();
    const interval = window.setInterval(refresh, 900);
    return () => { active = false; window.clearInterval(interval); };
  }, [credentials]);

  useEffect(() => {
    if (!credentials || pairing?.status !== "accepted") return undefined;
    let active = true;
    const poll = async () => {
      try {
        const { signals } = await takeQrSignals(credentials);
        for (const signal of signals) await handleSignal(signal);
      } catch (cause) {
        if (active) setError(directTransferError(cause));
      }
    };
    void poll();
    const interval = window.setInterval(poll, 650);
    return () => { active = false; window.clearInterval(interval); };
  }, [credentials, handleSignal, pairing?.status]);

  useEffect(() => {
    if (pairing?.status !== "accepted") return undefined;
    const transferTimeout = window.setTimeout(() => { void beginDirectTransfer(); }, 0);
    return () => window.clearTimeout(transferTimeout);
  }, [beginDirectTransfer, pairing?.status]);

  useEffect(() => () => closeConnection(), [closeConnection]);

  const createPair = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    if (!file) {
      setError("Choose one file to send.");
      return;
    }
    if (file.size > MAX_FILE_SIZE) {
      setError("The file must be 1 GB or smaller.");
      return;
    }
    setCreating(true);
    setError("");
    try {
      const created = await createQrPairing(file);
      const image = await QRCode.toDataURL(created.url, { errorCorrectionLevel: "M", margin: 1, width: 260 });
      startedRef.current = false;
      setCredentials({ pairToken: created.pairToken, role: "sender", secret: created.senderSecret });
      setPairing({ expiresAt: created.expiresAt, file: { name: file.name, size: file.size }, status: "waiting" });
      setQrImage(image);
      setTransferState("waiting");
    } catch (cause) {
      setError(directTransferError(cause));
    } finally {
      setCreating(false);
    }
  };

  const startAnother = () => {
    closeConnection();
    startedRef.current = false;
    setFile(null);
    setPairing(null);
    setCredentials(null);
    setQrImage("");
    setProgress(0);
    setError("");
    setTransferState("waiting");
    if (fileInputRef.current) fileInputRef.current.value = "";
  };

  const waitingCopy = pairing?.status === "claimed"
    ? "Your recipient scanned the code. They need to approve the file on their device."
    : "Scan this code with the recipient’s phone. Keep this page open until the transfer finishes.";

  return (
    <div className="page guest-upload-page">
      <header className="guest-upload-header">
        <a className="guest-upload-brand" href="/" aria-label="BabyShare home"><span className="guest-upload-brand-mark"><LightningMark /></span><span>BabyShare</span></a>
        <a className="guest-upload-home-link" href="/">Back to home</a>
      </header>
      <main className="guest-upload-shell">
        <section className="guest-upload-card" aria-labelledby="guest-upload-title">
          <div className="guest-upload-icon"><UploadIcon /></div>
          <p className="guest-upload-kicker">QR DIRECT TRANSFER</p>
          <h1 id="guest-upload-title">Send privately, without an upload.</h1>
          <p className="guest-upload-copy">Choose a file, then let the recipient scan your QR code. The file travels directly between your browsers.</p>

          {!pairing ? (
            <form className="guest-upload-form" onSubmit={createPair}>
              <label className="guest-file-field"><span>Select file</span><input ref={fileInputRef} type="file" required onChange={(event) => { setFile(event.target.files?.[0] || null); setError(""); }} /></label>
              {file && <p className="guest-selected-file" aria-live="polite"><strong>{file.name}</strong><span>{formatFileSize(file.size)}</span></p>}
              <button type="submit" className="guest-upload-submit" disabled={creating}>{creating ? "Preparing QR code…" : "Create QR code"}</button>
            </form>
          ) : (
            <div className="guest-success-card" aria-live="polite">
              <div className="guest-success-icon"><ShieldIcon /></div>
              <p className="guest-upload-kicker">{transferState === "complete" ? "TRANSFER COMPLETE" : "SCAN TO CONNECT"}</p>
              <h1>{transferState === "complete" ? "File sent directly." : transferState === "sending" ? `Sending ${progress}%` : "Scan this QR code."}</h1>
              {transferState === "complete" ? <p>The recipient now has the file in their browser. It was never uploaded to BabyShare.</p> : <p>{waitingCopy}</p>}
              {transferState !== "complete" && qrImage && <img className="guest-qr-image" src={qrImage} alt="QR code for the recipient to open this direct transfer" />}
              {transferState === "sending" && <div className="guest-upload-progress"><progress value={progress} max="100" /><span>{progress}%</span></div>}
              <button type="button" className="guest-upload-another" onClick={startAnother}>{transferState === "complete" ? "Send another file" : "Cancel and choose another file"}</button>
            </div>
          )}

          {error && <p className="guest-upload-error" role="alert">{error}</p>}
          <div className="guest-upload-notes" aria-label="QR direct transfer details"><span>1 file · up to 1 GB</span><span><ShieldIcon />Recipient approval required</span></div>
        </section>
      </main>
    </div>
  );
}
