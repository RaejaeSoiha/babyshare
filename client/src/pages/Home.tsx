import { useEffect, useRef, useState } from "react";
import type { DragEvent, FormEvent, PointerEvent } from "react";
import { createPortal } from "react-dom";
import { useLanTransfers } from "../components/LanTransfers";
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

function UsersIcon() {
  return (
    <svg viewBox="0 0 24 24" aria-hidden="true">
      <path d="M16 19v-1.1c0-2-1.8-3.6-4-3.6s-4 1.6-4 3.6V19m11-1v-.7c0-1.5-1-2.8-2.5-3.3M7.5 14C6 14.5 5 15.8 5 17.3v.7M12 11.5a3 3 0 1 0 0-6 3 3 0 0 0 0 6Zm5-1.4a2.4 2.4 0 1 0 0-4.8M7 10.1a2.4 2.4 0 1 1 0-4.8" fill="none" stroke="currentColor" strokeLinecap="round" strokeLinejoin="round" strokeWidth="1.6" />
    </svg>
  );
}

function ChatIcon() {
  return (
    <svg viewBox="0 0 24 24" aria-hidden="true">
      <path d="M6.3 17.6 3.8 20l.6-4.1A7.6 7.6 0 0 1 3 11.6C3 7.4 7 4 12 4s9 3.4 9 7.6-4 7.6-9 7.6c-1.1 0-2.2-.2-3.2-.5l-2.5-1.1Z" fill="none" stroke="currentColor" strokeLinecap="round" strokeLinejoin="round" strokeWidth="1.65" />
      <path d="M8.5 11.7h.01M12 11.7h.01M15.5 11.7h.01" fill="none" stroke="currentColor" strokeLinecap="round" strokeWidth="2.3" />
    </svg>
  );
}

function ShieldIcon() {
  return <svg viewBox="0 0 24 24" aria-hidden="true"><path d="M12 3 5 6v5.3c0 4.4 3 7.9 7 9.7 4-1.8 7-5.3 7-9.7V6l-7-3Zm-3.2 9 2.1 2.1 4.4-4.4" fill="none" stroke="currentColor" strokeLinecap="round" strokeLinejoin="round" strokeWidth="1.7" /></svg>;
}

function localGuestPath(result: GuestUploadResult, action: "preview" | "download") {
  const suppliedPath = action === "preview"
      ? result.previewPath
      : result.downloadPath;
  if (suppliedPath) return suppliedPath;

  try {
    const url = new URL(result.link);
    const token = url.searchParams.get("token");
    if (token) return `/guest-download?token=${encodeURIComponent(token)}&action=${action}`;
  } catch {
    // Fall back to the original share URL below when an older response is malformed.
  }
  return result.link;
}

function avatarInitial(name: string) {
  return name.trim().charAt(0).toUpperCase() || "G";
}

export default function Home() {
  const inputRef = useRef<HTMLInputElement>(null);
  const nearbyInputRef = useRef<HTMLInputElement>(null);
  const chatMessagesRef = useRef<HTMLDivElement>(null);
  const [account, setAccount] = useState<Account | null>(null);
  const [accountChecked, setAccountChecked] = useState(false);
  const [files, setFiles] = useState<File[]>([]);
  const [dragging, setDragging] = useState(false);
  const [loading, setLoading] = useState(false);
  const [progress, setProgress] = useState(0);
  const [error, setError] = useState("");
  const [guestResult, setGuestResult] = useState<GuestUploadResult | null>(null);
  const [userResult, setUserResult] = useState<UserUploadResult | null>(null);
  const [linkCopied, setLinkCopied] = useState(false);
  const [nearbyFiles, setNearbyFiles] = useState<File[]>([]);
  const [nearbyError, setNearbyError] = useState("");
  const [nearbySending, setNearbySending] = useState(false);
  const [nearbySearch, setNearbySearch] = useState("");
  const [chatDraft, setChatDraft] = useState("");
  const [selectedDeviceId, setSelectedDeviceId] = useState("");
  const [isNearbyDetailOpen, setIsNearbyDetailOpen] = useState(false);
  const [isNearbyPanelOpen, setIsNearbyPanelOpen] = useState(true);
  const [nearbyPanelPosition, setNearbyPanelPosition] = useState<{ left: number; top: number } | null>(null);
  const [nearbyDetailPosition, setNearbyDetailPosition] = useState<{ left: number; top: number } | null>(null);
  const [isCompactViewport, setIsCompactViewport] = useState(() => typeof window !== "undefined" && window.innerWidth <= 680);
  const nearbyPanelDragRef = useRef<{ height: number; left: number; offsetX: number; offsetY: number; pointerId: number; top: number; width: number } | null>(null);
  const nearbyDetailDragRef = useRef<{ height: number; left: number; offsetX: number; offsetY: number; pointerId: number; top: number; width: number } | null>(null);
  const {
    acceptChat,
    chats,
    devices,
    error: lanError,
    markChatRead,
    requestTransfers,
    requestChat,
    sendChatMessage,
    endChat,
    transfers,
    unreadChatIds,
  } = useLanTransfers();

  useEffect(() => {
    apiFetch("/api/me")
      .then((response) => response.ok ? response.json() as Promise<Account> : null)
      .then((data) => setAccount(data))
      .catch(() => setAccount(null))
      .finally(() => setAccountChecked(true));
  }, []);

  useEffect(() => {
    if (!isNearbyDetailOpen) return;
    const closeOnEscape = (event: KeyboardEvent) => {
      if (event.key === "Escape") {
        setIsNearbyDetailOpen(false);
        setIsNearbyPanelOpen(true);
      }
    };
    document.addEventListener("keydown", closeOnEscape);
    return () => document.removeEventListener("keydown", closeOnEscape);
  }, [isNearbyDetailOpen]);

  useEffect(() => {
    const updateViewport = () => setIsCompactViewport(window.innerWidth <= 680);
    updateViewport();
    window.addEventListener("resize", updateViewport);
    return () => window.removeEventListener("resize", updateViewport);
  }, []);

  useEffect(() => {
    const openRequestedChat = (event: Event) => {
      const peerId = (event as CustomEvent<{ peerId?: string }>).detail?.peerId;
      if (!peerId || !devices.some((device) => device.id === peerId)) return;
      setSelectedDeviceId(peerId);
      setNearbyFiles([]);
      setNearbyError("");
      setChatDraft("");
      setIsNearbyPanelOpen(false);
      setIsNearbyDetailOpen(true);
    };
    window.addEventListener("babyshare:open-chat", openRequestedChat);
    return () => window.removeEventListener("babyshare:open-chat", openRequestedChat);
  }, [devices]);

  const isSignedIn = Boolean(account);
  const guestPreviewPath = guestResult ? localGuestPath(guestResult, "preview") : "";
  const guestDownloadPath = guestResult ? localGuestPath(guestResult, "download") : "";
  const hasUploadResult = Boolean(guestResult || userResult);
  const selectedDevice = devices.find((device) => device.id === selectedDeviceId) ?? null;
  const selectedChat = chats.find((chat) => chat.peerId === selectedDeviceId) ?? null;
  const activeOutgoingTransfers = transfers.filter((transfer) => transfer.direction === "outgoing"
    && ["pending", "accepted", "receiving", "ready"].includes(transfer.status)).slice(0, 3);
  const incomingChats = chats.filter((chat) => chat.direction === "incoming" && chat.status === "pending").slice(0, 3);
  const nearbyAlertCount = incomingChats.length + unreadChatIds.length;
  const nearbyUsers = devices
    .filter((device) => `${device.displayName} ${device.deviceName}`.toLowerCase().includes(nearbySearch.trim().toLowerCase()))
    .sort((left, right) => {
      const leftChat = chats.find((chat) => chat.peerId === left.id && chat.status === "active");
      const rightChat = chats.find((chat) => chat.peerId === right.id && chat.status === "active");
      const leftPriority = Number(Boolean(leftChat && unreadChatIds.includes(leftChat.id))) * 2 + Number(Boolean(leftChat));
      const rightPriority = Number(Boolean(rightChat && unreadChatIds.includes(rightChat.id))) * 2 + Number(Boolean(rightChat));
      return rightPriority - leftPriority || left.displayName.localeCompare(right.displayName);
    });

  useEffect(() => {
    if (!isNearbyDetailOpen || selectedChat?.status !== "active") return;
    markChatRead(selectedChat.id);
    const animationFrame = window.requestAnimationFrame(() => {
      chatMessagesRef.current?.scrollTo({ behavior: "smooth", top: chatMessagesRef.current.scrollHeight });
    });
    return () => window.cancelAnimationFrame(animationFrame);
  }, [isNearbyDetailOpen, markChatRead, selectedChat?.id, selectedChat?.messages.length, selectedChat?.status]);

  const selectFiles = (nextFiles: FileList | File[]) => {
    const selected = Array.from(nextFiles);
    setError("");
    setGuestResult(null);
    setUserResult(null);
    setLinkCopied(false);

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
    setLinkCopied(false);
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

  const uploadAnotherFile = () => {
    setFiles([]);
    setProgress(0);
    setError("");
    setGuestResult(null);
    setUserResult(null);
    setLinkCopied(false);
    if (inputRef.current) inputRef.current.value = "";
  };

  const copyGuestLink = async () => {
    if (!guestResult) return;
    try {
      if (navigator.clipboard?.writeText && window.isSecureContext) {
        await navigator.clipboard.writeText(guestResult.link);
      } else {
        const copyTarget = document.createElement("textarea");
        copyTarget.value = guestResult.link;
        copyTarget.setAttribute("readonly", "");
        copyTarget.style.position = "fixed";
        copyTarget.style.opacity = "0";
        document.body.append(copyTarget);
        copyTarget.select();
        const copied = document.execCommand("copy");
        copyTarget.remove();
        if (!copied) throw new Error("copy_failed");
      }
      setLinkCopied(true);
    } catch {
      setError("Could not copy the share link. Please try again.");
    }
  };

  const selectNearbyDevice = (deviceId: string) => {
    setSelectedDeviceId(deviceId);
    setNearbyFiles([]);
    setNearbyError("");
    setChatDraft("");
    if (nearbyInputRef.current) nearbyInputRef.current.value = "";
  };

  const openNearbyDetail = (deviceId: string) => {
    selectNearbyDevice(deviceId);
    setIsNearbyPanelOpen(false);
    setIsNearbyDetailOpen(true);
  };

  const closeNearbyDetail = () => {
    setIsNearbyDetailOpen(false);
    setIsNearbyPanelOpen(true);
  };

  const chooseNearbyFiles = (nextFiles: FileList | File[]) => {
    const selected = Array.from(nextFiles);
    if (selected.length === 0) return;
    if (selected.length > 20) {
      setNearbyFiles([]);
      setNearbyError("Choose up to 20 files at a time.");
      return;
    }
    if (selected.some((file) => file.size > MAX_FILE_SIZE)) {
      setNearbyFiles([]);
      setNearbyError("Each file must be 1 GB or smaller.");
      return;
    }
    setNearbyFiles(selected);
    setNearbyError("");
  };

  const clearNearbyFiles = () => {
    setNearbyFiles([]);
    if (nearbyInputRef.current) nearbyInputRef.current.value = "";
  };

  const sendToNearbyDevice = async () => {
    if (!selectedDevice || nearbyFiles.length === 0 || nearbySending) return;
    setNearbySending(true);
    setNearbyError("");
    try {
      await requestTransfers(selectedDevice.id, nearbyFiles);
      setNearbyFiles([]);
      if (nearbyInputRef.current) nearbyInputRef.current.value = "";
    } catch (transferError) {
      const code = transferError instanceof Error ? transferError.message : "";
      setNearbyError(code === "device_unavailable"
        ? "That device is no longer available. Choose another device."
        : code === "transfer_limit_reached"
          ? "Finish or decline existing file requests before sending more."
          : "Could not create the transfer request. Please try again.");
    } finally {
      setNearbySending(false);
    }
  };

  const startPrivateChat = async () => {
    if (!selectedDevice) return;
    setNearbyError("");
    try {
      await requestChat(selectedDevice.id);
    } catch {
      setNearbyError("Could not start the private chat. Please try again.");
    }
  };

  const submitChatMessage = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    if (!selectedChat || !chatDraft.trim()) return;
    setNearbyError("");
    try {
      await sendChatMessage(selectedChat.id, chatDraft);
      setChatDraft("");
    } catch {
      setNearbyError("Could not send the message. Keep the chat open and try again.");
    }
  };

  const endSelectedChat = async () => {
    if (!selectedChat) return;
    setNearbyError("");
    try {
      await endChat(selectedChat.id);
      setChatDraft("");
    } catch {
      setNearbyError("Could not end the chat. Please try again.");
    }
  };

  const declineIncomingChat = async (chatId: string) => {
    try {
      await endChat(chatId);
    } catch {
      setNearbyError("Could not decline the chat request. Please try again.");
    }
  };

  const acceptIncomingChat = async (chatId: string, peerId: string) => {
    setNearbyError("");
    try {
      await acceptChat(chatId);
      openNearbyDetail(peerId);
    } catch {
      setNearbyError("Could not accept the chat request. Please try again.");
    }
  };

  const startMovingNearbyPanel = (event: PointerEvent<HTMLElement>) => {
    if (event.button !== 0 || isCompactViewport) return;
    const panel = event.currentTarget.closest(".nearby-users-panel") as HTMLElement | null;
    if (!panel) return;
    const rect = panel.getBoundingClientRect();
    nearbyPanelDragRef.current = {
      height: rect.height,
      left: rect.left,
      offsetX: event.clientX - rect.left,
      offsetY: event.clientY - rect.top,
      pointerId: event.pointerId,
      top: rect.top,
      width: rect.width,
    };
    event.currentTarget.setPointerCapture(event.pointerId);
  };

  const moveNearbyPanel = (event: PointerEvent<HTMLElement>) => {
    const drag = nearbyPanelDragRef.current;
    if (!drag || drag.pointerId !== event.pointerId) return;
    const left = Math.round(Math.min(Math.max(12, event.clientX - drag.offsetX), window.innerWidth - drag.width - 12));
    const top = Math.round(Math.min(Math.max(12, event.clientY - drag.offsetY), window.innerHeight - drag.height - 12));
    setNearbyPanelPosition({ left, top });
  };

  const stopMovingNearbyPanel = (event: PointerEvent<HTMLElement>) => {
    const drag = nearbyPanelDragRef.current;
    if (!drag || drag.pointerId !== event.pointerId) return;
    nearbyPanelDragRef.current = null;
    if (event.currentTarget.hasPointerCapture(event.pointerId)) event.currentTarget.releasePointerCapture(event.pointerId);
  };

  const startMovingNearbyDetail = (event: PointerEvent<HTMLElement>) => {
    if (event.button !== 0 || isCompactViewport) return;
    const dialog = event.currentTarget.closest(".nearby-detail-dialog") as HTMLElement | null;
    if (!dialog) return;
    const rect = dialog.getBoundingClientRect();
    nearbyDetailDragRef.current = {
      height: rect.height,
      left: rect.left,
      offsetX: event.clientX - rect.left,
      offsetY: event.clientY - rect.top,
      pointerId: event.pointerId,
      top: rect.top,
      width: rect.width,
    };
    event.currentTarget.setPointerCapture(event.pointerId);
  };

  const moveNearbyDetail = (event: PointerEvent<HTMLElement>) => {
    const drag = nearbyDetailDragRef.current;
    if (!drag || drag.pointerId !== event.pointerId) return;
    const left = Math.round(Math.min(Math.max(12, event.clientX - drag.offsetX), window.innerWidth - drag.width - 12));
    const top = Math.round(Math.min(Math.max(12, event.clientY - drag.offsetY), window.innerHeight - drag.height - 12));
    setNearbyDetailPosition({ left, top });
  };

  const stopMovingNearbyDetail = (event: PointerEvent<HTMLElement>) => {
    const drag = nearbyDetailDragRef.current;
    if (!drag || drag.pointerId !== event.pointerId) return;
    nearbyDetailDragRef.current = null;
    if (event.currentTarget.hasPointerCapture(event.pointerId)) event.currentTarget.releasePointerCapture(event.pointerId);
  };

  const restoreNearbyPanel = () => {
    // A minimized panel always returns to the visible lower-right corner.
    // The expanded panel remains draggable, but it can never be reopened off-screen.
    setNearbyPanelPosition(null);
    setIsNearbyPanelOpen(true);
  };

  const minimizeNearbyPanel = () => {
    // Keep the minimized control in one predictable place instead of leaving it
    // wherever the expanded panel was last dragged.
    setNearbyPanelPosition(null);
    setIsNearbyPanelOpen(false);
  };

  const nearbyPanelStyle = nearbyPanelPosition && !isCompactViewport
    ? { bottom: "auto", left: nearbyPanelPosition.left, right: "auto", top: nearbyPanelPosition.top, transform: "none" }
    : undefined;
  const nearbyDetailStyle = nearbyDetailPosition && !isCompactViewport
    ? { bottom: "auto", left: nearbyDetailPosition.left, right: "auto", top: nearbyDetailPosition.top, transform: "none" }
    : undefined;

  return (
    <div className="home-page">
      <header className="site-header">
        <a className="brand" href="/" aria-label="BabyShare home">
          <span className="brand-mark"><LightningMark /></span>
          <span>BabyShare</span>
        </a>
        <nav className="home-nav" aria-label="Account navigation">
          {isSignedIn ? (
            <a className="nav-action" href="/dashboard">Workspace</a>
          ) : (
            <a className="nav-action" href="/login">Log in</a>
          )}
        </nav>
      </header>

      <main className={`home-main${hasUploadResult ? " has-upload-result" : ""}${isNearbyDetailOpen ? " has-nearby-detail" : ""}`}>
        <section className="home-hero" aria-labelledby="home-title">
          <h1 id="home-title">Baby<span>Share</span></h1>
        </section>

        {!hasUploadResult && <section className="feature-indicators" aria-label="BabyShare features">
          <article>
            <span className="indicator-icon private"><ShieldIcon /></span>
            <div><h2>Private Sharing</h2><p>Your files stay on your network.</p></div>
          </article>
          <article>
            <span className="indicator-icon fast"><UsersIcon /></span>
            <div><h2>Nearby Colleagues</h2><p>See active people on your LAN.</p></div>
          </article>
          <article>
            <span className="indicator-icon expiry"><ChatIcon /></span>
            <div><h2>Ephemeral Chat</h2><p>Conversations vanish when ended.</p></div>
          </article>
        </section>}

        <section className="upload-section" aria-label="File upload">
          {!hasUploadResult ? (
            <>
              <div className="home-action-grid">
              <section className="upload-share-card" aria-labelledby="upload-share-title">
                <div className="action-card-heading">
                  <span className="action-card-icon"><UploadArrow /></span>
                  <div>
                    <h2 id="upload-share-title">Upload &amp; Share Link</h2>
                    <p>Create an encrypted link for your trusted team or network.</p>
                  </div>
                </div>
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
                  <button className="browse-button" type="button" onClick={() => inputRef.current?.click()} disabled={loading}>{isSignedIn ? "Choose files" : "Choose file"}</button>
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
              </section>

              </div>
              {isNearbyDetailOpen && selectedDevice && createPortal(
                  <section className="nearby-detail-dialog" style={nearbyDetailStyle} role="dialog" aria-labelledby="nearby-detail-title">
                    <header className="nearby-detail-header" onPointerDown={startMovingNearbyDetail} onPointerMove={moveNearbyDetail} onPointerUp={stopMovingNearbyDetail} onPointerCancel={stopMovingNearbyDetail} title="Drag to move chat">
                      <div className="nearby-detail-user">
                        <span className="nearby-user-avatar is-large" aria-hidden="true">{avatarInitial(selectedDevice.displayName)}</span>
                        <div>
                          <p className="nearby-kicker">Nearby colleague</p>
                          <h2 id="nearby-detail-title">{selectedDevice.displayName}</h2>
                          <p>{selectedDevice.displayName === "Guest" ? `Guest • ${selectedDevice.deviceName}` : selectedDevice.deviceName} <span className="nearby-detail-online"><span aria-hidden="true" />Online</span></p>
                        </div>
                      </div>
                      <div className="nearby-detail-actions">
                        {selectedChat?.status === "active" && <button type="button" className="lan-decline private-chat-end" onPointerDown={(event) => event.stopPropagation()} onClick={() => void endSelectedChat()}>End chat</button>}
                        <button type="button" className="nearby-detail-close" onPointerDown={(event) => event.stopPropagation()} onClick={closeNearbyDetail} aria-label="Close nearby user details">×</button>
                      </div>
                    </header>

                    <div className="nearby-detail-body">
                      <input
                        ref={nearbyInputRef}
                        className="visually-hidden"
                        type="file"
                        multiple
                        onChange={(event) => event.target.files && chooseNearbyFiles(event.target.files)}
                        aria-label="Choose files for nearby user"
                      />
                      {selectedChat?.status === "active" ? (
                        <section className="private-chat" aria-label={`Private chat with ${selectedDevice.displayName}`}>
                          {selectedChat.messages.length > 0 && <div className="private-chat-messages" ref={chatMessagesRef} aria-live="polite">
                            {selectedChat.messages.map((message) => (
                              <div className={`chat-message${message.mine ? " is-mine" : ""}`} key={message.id}>
                                <span>{message.text}</span>
                                <time dateTime={new Date(message.sentAt).toISOString()}>{new Date(message.sentAt).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" })}</time>
                              </div>
                            ))}
                          </div>}
                          <form className="private-chat-compose" onSubmit={submitChatMessage}>
                            <label className="visually-hidden" htmlFor="private-chat-message">Message</label>
                            <button type="button" className="chat-attachment-button" onClick={() => nearbyInputRef.current?.click()} aria-label="Add files to transfer" title="Add files">+</button>
                            <input id="private-chat-message" value={chatDraft} maxLength={1000} onChange={(event) => setChatDraft(event.target.value)} placeholder="Write a message" autoComplete="off" />
                            <button type="submit" className="nearby-send" disabled={!chatDraft.trim()}>Send</button>
                          </form>
                          {nearbyFiles.length > 0 && <div className="chat-file-tray" aria-live="polite">
                            <div><strong>{nearbyFiles.length} {nearbyFiles.length === 1 ? "file" : "files"} ready</strong><small>{nearbyFiles.map((file) => `${file.name} (${formatFileSize(file.size)})`).join(" · ")}</small></div>
                            <button type="button" className="chat-file-clear" onClick={clearNearbyFiles} aria-label="Remove selected files">×</button>
                            <button type="button" className="chat-file-send" disabled={nearbySending} onClick={() => void sendToNearbyDevice()}>{nearbySending ? "Sending…" : "Send files"}</button>
                          </div>}
                        </section>
                      ) : (
                        <div className="nearby-compose">
                          <div className="nearby-compose-actions">
                            {!selectedChat && <button type="button" className="nearby-send" onClick={() => void startPrivateChat()}>Start chat</button>}
                            <button type="button" className="nearby-choose" onClick={() => nearbyInputRef.current?.click()}>Choose files</button>
                            <button type="button" className="nearby-send" disabled={nearbyFiles.length === 0 || nearbySending} onClick={() => void sendToNearbyDevice()}>
                              {nearbySending ? "Sending…" : nearbyFiles.length ? `Send ${nearbyFiles.length} ${nearbyFiles.length === 1 ? "file" : "files"}` : "Send files"}
                            </button>
                          </div>
                          {nearbyFiles.length > 0 && <p className="nearby-files" aria-live="polite">{nearbyFiles.map((file) => `${file.name} (${formatFileSize(file.size)})`).join(" · ")}</p>}
                          {selectedChat?.status === "pending" && (
                            <div className="private-chat-pending">
                              <p>Chat request sent.</p>
                              <button type="button" className="lan-decline" onClick={() => void endSelectedChat()}>Cancel</button>
                            </div>
                          )}
                          <p className="nearby-privacy-note">Ephemeral · recipient approves files</p>
                        </div>
                      )}
                      {activeOutgoingTransfers.length > 0 && (
                        <div className="nearby-transfer-list" aria-live="polite">
                          {activeOutgoingTransfers.map((transfer) => (
                            <div className="nearby-transfer" key={transfer.id}>
                              <div><strong>{transfer.name}</strong><span>To {transfer.peerName}</span></div>
                              <div className="nearby-transfer-status">
                                <span>{transfer.status === "pending" ? "Awaiting acceptance" : transfer.status === "accepted" ? transfer.transport === "peer" ? "Approved — connecting directly…" : "Approved — sending…" : transfer.status === "receiving" ? `${transfer.transport === "peer" ? "Sending directly" : "Sending"} ${transfer.progress}%` : transfer.transport === "peer" ? "Delivered directly" : "Ready to download once"}</span>
                                {(transfer.status === "receiving" || transfer.status === "ready") && <progress max="100" value={transfer.progress} />}
                              </div>
                            </div>
                          ))}
                        </div>
                      )}
                      {nearbyError && <p className="error nearby-error" role="alert">{nearbyError}</p>}
                    </div>
                  </section>,
                document.body,
              )}
            </>
          ) : guestResult ? (
            <div className="upload-success-card" aria-live="polite">
              <h2>File uploaded successfully</h2>
              <div className="success-card-actions">
                <button className="copy-link-button" type="button" onClick={copyGuestLink}>{linkCopied ? "Copied" : "Copy Link"}</button>
                <div className="success-secondary-actions">
                  <a href={apiUrl(guestPreviewPath)} target="_blank" rel="noreferrer">Preview</a>
                  <a href={apiUrl(guestDownloadPath)} target="_blank" rel="noreferrer">Download</a>
                </div>
                <button className="upload-another-button" type="button" onClick={uploadAnotherFile}>Upload Another File</button>
              </div>
              {error && <p className="error home-error" role="alert">{error}</p>}
            </div>
          ) : (
            <div className="upload-success-card" aria-live="polite">
              <h2>{userResult?.links.length === 1 ? "File uploaded successfully" : "Files uploaded successfully"}</h2>
              <div className="success-card-actions">
                <a className="copy-link-button" href="/dashboard">Open Dashboard</a>
                <button className="upload-another-button" type="button" onClick={uploadAnotherFile}>Upload Another File</button>
              </div>
            </div>
          )}
        </section>

      </main>

      {!hasUploadResult && !isNearbyDetailOpen && (isNearbyPanelOpen ? (
        <aside className="nearby-users-panel" style={nearbyPanelStyle} aria-label="Nearby users and chat">
          <header className="nearby-users-panel-header">
            <div
              className="nearby-users-panel-title"
              onPointerDown={startMovingNearbyPanel}
              onPointerMove={moveNearbyPanel}
              onPointerUp={stopMovingNearbyPanel}
              onPointerCancel={stopMovingNearbyPanel}
              title="Drag to move Nearby Users"
            >
              <span className="nearby-users-panel-icon"><UsersIcon /></span>
              <div>
                <p className="nearby-kicker">Company LAN · private</p>
                <div className="nearby-users-panel-heading-row"><h2>Nearby Users</h2><span className="nearby-online-count"><i aria-hidden="true" />{devices.length} online</span></div>
              </div>
            </div>
            <button type="button" className="nearby-users-panel-toggle" onClick={minimizeNearbyPanel} aria-label="Minimize Nearby Users">−</button>
          </header>
          {lanError && <p className="error nearby-panel-error" role="alert">{lanError}</p>}
          {devices.length > 6 && (
            <label className="nearby-user-search">
              <span className="visually-hidden">Search nearby users</span>
              <input type="search" value={nearbySearch} onChange={(event) => setNearbySearch(event.target.value)} placeholder="Search nearby users" />
            </label>
          )}
          <div className="nearby-users-panel-list" aria-live="polite">
            {devices.length === 0 ? (
              <p className="nearby-empty">No colleagues are online yet. Ask a teammate to open BabyShare on this network.</p>
            ) : nearbyUsers.length === 0 ? (
              <p className="nearby-empty">No nearby users match that search.</p>
            ) : nearbyUsers.map((device) => {
              const deviceChat = chats.find((chat) => chat.peerId === device.id && chat.status === "active");
              const lastMessage = deviceChat?.messages.at(-1);
              const hasUnreadMessage = Boolean(deviceChat && unreadChatIds.includes(deviceChat.id));
              return (
              <article className={`nearby-panel-user${hasUnreadMessage ? " has-unread" : ""}`} key={device.id}>
                <button
                  type="button"
                  className="nearby-panel-user-select"
                  onClick={() => openNearbyDetail(device.id)}
                  aria-label={`Open chat and sharing with ${device.displayName} on ${device.deviceName}`}
                >
                  <span className="nearby-user-avatar" aria-hidden="true"><i />{avatarInitial(device.displayName)}</span>
                  <span className="nearby-device-details">
                    <strong>{device.displayName}</strong>
                    <small className={hasUnreadMessage ? "nearby-chat-preview is-unread" : "nearby-chat-preview"}>{lastMessage?.text || (device.displayName === "Guest" ? `Guest • ${device.deviceName}` : device.deviceName)}</small>
                  </span>
                  <span className="nearby-device-online"><span aria-hidden="true" />Online</span>
                  <span className="nearby-panel-user-arrow" aria-hidden="true">›</span>
                  {hasUnreadMessage && <span className="nearby-chat-unread" aria-label="New message" />}
                </button>
              </article>
              );
            })}
          </div>
          {incomingChats.length > 0 && (
            <section className="nearby-panel-requests" aria-label="Incoming private chat requests">
              <p className="nearby-panel-section-title">Chat requests</p>
              {incomingChats.map((chat) => (
                <article className="nearby-panel-request" key={chat.id}>
                  <p><strong>{chat.peerName}</strong> wants to start a chat.</p>
                  <div>
                    <button type="button" className="lan-accept" onClick={() => void acceptIncomingChat(chat.id, chat.peerId)}>Accept</button>
                    <button type="button" className="lan-decline" onClick={() => void declineIncomingChat(chat.id)}>Decline</button>
                  </div>
                </article>
              ))}
            </section>
          )}
          {nearbyError && <p className="error nearby-panel-error" role="alert">{nearbyError}</p>}
        </aside>
      ) : (
        <button
          type="button"
          className="nearby-users-tab"
          onClick={restoreNearbyPanel}
          aria-label="Open Nearby Users"
        >
          <UsersIcon />
          <span>Nearby Users</span>
          {nearbyAlertCount > 0 && <span className="nearby-users-tab-alert" aria-label={`${nearbyAlertCount} new chat item${nearbyAlertCount === 1 ? "" : "s"}`} />}
        </button>
      ))}

      <footer className="site-footer">Encrypted sharing · Recipient-approved transfers · Ephemeral chat</footer>
    </div>
  );
}
