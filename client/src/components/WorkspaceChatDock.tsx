import { useEffect, useMemo, useRef, useState } from "react";
import type { FormEvent, PointerEvent } from "react";
import { Link, useLocation } from "react-router-dom";
import { useLanTransfers } from "./LanTransfers";
import { apiFetch } from "../lib/api";

const MAX_FILE_SIZE = 1024 * 1024 * 1024;

function avatarInitial(name: string) {
  return name.trim().charAt(0).toUpperCase() || "G";
}

function formatFileSize(bytes: number) {
  if (bytes < 1024) return `${bytes} B`;
  const units = ["KB", "MB", "GB"];
  const unitIndex = Math.min(Math.floor(Math.log(bytes) / Math.log(1024)) - 1, units.length - 1);
  const value = bytes / (1024 ** (unitIndex + 1));
  return `${value >= 10 ? value.toFixed(0) : value.toFixed(1)} ${units[unitIndex]}`;
}

function UsersIcon() {
  return (
    <svg viewBox="0 0 24 24" aria-hidden="true">
      <path d="M16 19v-1.1c0-2-1.8-3.6-4-3.6s-4 1.6-4 3.6V19m11-1v-.7c0-1.5-1-2.8-2.5-3.3M7.5 14C6 14.5 5 15.8 5 17.3v.7M12 11.5a3 3 0 1 0 0-6 3 3 0 0 0 0 6Zm5-1.4a2.4 2.4 0 1 0 0-4.8M7 10.1a2.4 2.4 0 1 1 0-4.8" fill="none" stroke="currentColor" strokeLinecap="round" strokeLinejoin="round" strokeWidth="1.6" />
    </svg>
  );
}

function BackIcon() {
  return <svg viewBox="0 0 24 24" aria-hidden="true"><path d="m14.5 5-7 7 7 7M8 12h10" fill="none" stroke="currentColor" strokeLinecap="round" strokeLinejoin="round" strokeWidth="1.8" /></svg>;
}

export default function WorkspaceChatDock() {
  const { pathname } = useLocation();
  const messagesRef = useRef<HTMLDivElement>(null);
  const attachmentInputRef = useRef<HTMLInputElement>(null);
  const [isSignedIn, setIsSignedIn] = useState<boolean | null>(null);
  const [isOpen, setIsOpen] = useState(false);
  const [selectedPeerId, setSelectedPeerId] = useState("");
  const [draft, setDraft] = useState("");
  const [attachments, setAttachments] = useState<File[]>([]);
  const [sendingAttachments, setSendingAttachments] = useState(false);
  const [error, setError] = useState("");
  const [dockPosition, setDockPosition] = useState<{ left: number; top: number } | null>(null);
  const [isCompactViewport, setIsCompactViewport] = useState(() => typeof window !== "undefined" && window.innerWidth <= 680);
  const dockDragRef = useRef<{ height: number; left: number; offsetX: number; offsetY: number; pointerId: number; top: number; width: number } | null>(null);
  const {
    acceptChat,
    chats,
    devices,
    endChat,
    markChatRead,
    requestChat,
    requestTransfers,
    sendChatMessage,
    unreadChatIds,
  } = useLanTransfers();

  const isWorkspaceRoute = pathname === "/dashboard" || pathname === "/files" || pathname === "/admin";

  useEffect(() => {
    let active = true;
    void apiFetch("/api/me")
      .then((response) => active && setIsSignedIn(response.ok))
      .catch(() => active && setIsSignedIn(false));
    return () => { active = false; };
  }, []);

  useEffect(() => {
    const updateViewport = () => setIsCompactViewport(window.innerWidth <= 680);
    updateViewport();
    window.addEventListener("resize", updateViewport);
    return () => window.removeEventListener("resize", updateViewport);
  }, []);

  useEffect(() => {
    if (!isWorkspaceRoute) return;
    const openRequestedChat = (event: Event) => {
      const peerId = (event as CustomEvent<{ peerId?: string }>).detail?.peerId;
      if (!peerId) return;
      setAttachments([]);
      if (attachmentInputRef.current) attachmentInputRef.current.value = "";
      setSelectedPeerId(peerId);
      setIsOpen(true);
      setError("");
    };
    window.addEventListener("babyshare:open-chat", openRequestedChat);
    return () => window.removeEventListener("babyshare:open-chat", openRequestedChat);
  }, [isWorkspaceRoute]);

  const sortedUsers = useMemo(() => [...devices].sort((left, right) => {
    const leftChat = chats.find((chat) => chat.peerId === left.id && chat.status === "active");
    const rightChat = chats.find((chat) => chat.peerId === right.id && chat.status === "active");
    const leftPriority = Number(Boolean(leftChat && unreadChatIds.includes(leftChat.id))) * 2 + Number(Boolean(leftChat));
    const rightPriority = Number(Boolean(rightChat && unreadChatIds.includes(rightChat.id))) * 2 + Number(Boolean(rightChat));
    return rightPriority - leftPriority || left.displayName.localeCompare(right.displayName);
  }), [chats, devices, unreadChatIds]);
  const selectedChat = chats.find((chat) => chat.peerId === selectedPeerId) ?? null;
  const selectedUser = devices.find((device) => device.id === selectedPeerId) ?? null;
  const selectedName = selectedUser?.displayName || selectedChat?.peerName || "Nearby user";
  const activeChatId = selectedChat?.status === "active" ? selectedChat.id : "";
  const activeMessageCount = selectedChat?.status === "active" ? selectedChat.messages.length : 0;
  const newItemCount = unreadChatIds.length + chats.filter((chat) => chat.direction === "incoming" && chat.status === "pending").length;

  useEffect(() => {
    if (!activeChatId) return;
    markChatRead(activeChatId);
    const frame = window.requestAnimationFrame(() => {
      messagesRef.current?.scrollTo({ behavior: "smooth", top: messagesRef.current.scrollHeight });
    });
    return () => window.cancelAnimationFrame(frame);
  }, [activeChatId, activeMessageCount, markChatRead]);

  if (!isWorkspaceRoute || !isSignedIn) return null;

  const openUser = async (peerId: string) => {
    setSelectedPeerId(peerId);
    setIsOpen(true);
    setError("");
    setAttachments([]);
    if (attachmentInputRef.current) attachmentInputRef.current.value = "";
    const existing = chats.find((chat) => chat.peerId === peerId);
    if (existing) return;
    try {
      await requestChat(peerId);
    } catch {
      setError("Could not start the chat. Please try again.");
    }
  };

  const acceptSelectedChat = async () => {
    if (!selectedChat) return;
    setError("");
    try {
      await acceptChat(selectedChat.id);
    } catch {
      setError("Could not accept the chat request. Please try again.");
    }
  };

  const endSelectedChat = async () => {
    if (!selectedChat) return;
    setError("");
    try {
      await endChat(selectedChat.id);
      setSelectedPeerId("");
      setDraft("");
      setAttachments([]);
      if (attachmentInputRef.current) attachmentInputRef.current.value = "";
    } catch {
      setError("Could not end the chat. Please try again.");
    }
  };

  const sendMessage = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    if (!selectedChat || !draft.trim()) return;
    setError("");
    try {
      await sendChatMessage(selectedChat.id, draft);
      setDraft("");
    } catch {
      setError("Could not send the message. Please try again.");
    }
  };

  const chooseAttachments = (nextFiles: FileList | File[]) => {
    const selected = Array.from(nextFiles);
    if (selected.length === 0) return;
    if (selected.length > 20) {
      setAttachments([]);
      setError("Choose up to 20 files at a time.");
      return;
    }
    if (selected.some((file) => file.size > MAX_FILE_SIZE)) {
      setAttachments([]);
      setError("Each file must be 1 GB or smaller.");
      return;
    }
    setAttachments(selected);
    setError("");
  };

  const clearAttachments = () => {
    setAttachments([]);
    if (attachmentInputRef.current) attachmentInputRef.current.value = "";
  };

  const sendAttachments = async () => {
    if (!selectedPeerId || attachments.length === 0 || sendingAttachments) return;
    setSendingAttachments(true);
    setError("");
    try {
      await requestTransfers(selectedPeerId, attachments);
      clearAttachments();
    } catch (transferError) {
      setError(transferError instanceof Error && transferError.message === "transfer_limit_reached"
        ? "Finish or decline existing file requests before sending more."
        : "Could not send the file request. Please try again.");
    } finally {
      setSendingAttachments(false);
    }
  };

  const startMovingDock = (event: PointerEvent<HTMLElement>) => {
    if (event.button !== 0 || isCompactViewport) return;
    const dock = event.currentTarget.closest(".workspace-chat-dock") as HTMLElement | null;
    if (!dock) return;
    const rect = dock.getBoundingClientRect();
    dockDragRef.current = {
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

  const moveDock = (event: PointerEvent<HTMLElement>) => {
    const drag = dockDragRef.current;
    if (!drag || drag.pointerId !== event.pointerId) return;
    const left = Math.round(Math.min(Math.max(12, event.clientX - drag.offsetX), window.innerWidth - drag.width - 12));
    const top = Math.round(Math.min(Math.max(12, event.clientY - drag.offsetY), window.innerHeight - drag.height - 12));
    setDockPosition({ left, top });
  };

  const stopMovingDock = (event: PointerEvent<HTMLElement>) => {
    const drag = dockDragRef.current;
    if (!drag || drag.pointerId !== event.pointerId) return;
    dockDragRef.current = null;
    if (event.currentTarget.hasPointerCapture(event.pointerId)) event.currentTarget.releasePointerCapture(event.pointerId);
  };

  const dockStyle = dockPosition && !isCompactViewport
    ? { bottom: "auto", left: dockPosition.left, right: "auto", top: dockPosition.top, transform: "none" }
    : undefined;

  return isOpen ? (
    <aside className="workspace-chat-dock" style={dockStyle} aria-label="Nearby Users chat">
      {selectedPeerId ? (
        <>
          <header className="workspace-chat-header" onPointerDown={startMovingDock} onPointerMove={moveDock} onPointerUp={stopMovingDock} onPointerCancel={stopMovingDock} title="Drag to move chat">
            <button type="button" className="workspace-chat-back" onPointerDown={(event) => event.stopPropagation()} onClick={() => setSelectedPeerId("")} aria-label="Back to Nearby Users"><BackIcon /></button>
            <div className="workspace-chat-title"><p>Nearby User</p><strong>{selectedName}</strong></div>
            <button type="button" className="workspace-chat-minimize" onPointerDown={(event) => event.stopPropagation()} onClick={() => setIsOpen(false)} aria-label="Minimize chat">−</button>
          </header>
          <div className="workspace-chat-thread">
            {selectedChat?.status === "active" ? (
              <>
                <input ref={attachmentInputRef} className="visually-hidden" type="file" multiple onChange={(event) => event.target.files && chooseAttachments(event.target.files)} aria-label="Add files to transfer" />
                <div className="workspace-chat-messages" ref={messagesRef} aria-live="polite">
                  {selectedChat.messages.length === 0 ? <p>Send the first message. Ending this chat deletes it for both people.</p> : selectedChat.messages.map((message) => (
                    <div className={`workspace-chat-message${message.mine ? " is-mine" : ""}`} key={message.id}>{message.text}</div>
                  ))}
                </div>
                <form className="workspace-chat-compose" onSubmit={sendMessage}>
                  <button type="button" className="chat-attachment-button" onClick={() => attachmentInputRef.current?.click()} aria-label="Add files to transfer" title="Add files">+</button>
                  <input value={draft} maxLength={1000} onChange={(event) => setDraft(event.target.value)} placeholder="Write a message" aria-label="Write a message" autoComplete="off" />
                  <button type="submit" disabled={!draft.trim()}>Send</button>
                </form>
                {attachments.length > 0 && <div className="chat-file-tray" aria-live="polite">
                  <div><strong>{attachments.length} {attachments.length === 1 ? "file" : "files"} ready</strong><small>{attachments.map((file) => `${file.name} (${formatFileSize(file.size)})`).join(" · ")}</small></div>
                  <button type="button" className="chat-file-clear" onClick={clearAttachments} aria-label="Remove selected files">×</button>
                  <button type="button" className="chat-file-send" disabled={sendingAttachments} onClick={() => void sendAttachments()}>{sendingAttachments ? "Sending…" : "Send files"}</button>
                </div>}
                <button type="button" className="workspace-chat-end" onClick={() => void endSelectedChat()}>End chat · delete messages</button>
              </>
            ) : selectedChat?.direction === "incoming" ? (
              <div className="workspace-chat-state"><p>{selectedName} wants to start a private chat.</p><button type="button" onClick={() => void acceptSelectedChat()}>Accept chat</button><button type="button" className="workspace-chat-end" onClick={() => void endSelectedChat()}>Decline</button></div>
            ) : selectedChat ? (
              <div className="workspace-chat-state"><p>Chat request sent. Waiting for {selectedName} to accept.</p><button type="button" className="workspace-chat-end" onClick={() => void endSelectedChat()}>Cancel request</button></div>
            ) : null}
            {error && <p className="workspace-chat-error" role="alert">{error}</p>}
          </div>
        </>
      ) : (
        <>
          <header className="workspace-chat-header" onPointerDown={startMovingDock} onPointerMove={moveDock} onPointerUp={stopMovingDock} onPointerCancel={stopMovingDock} title="Drag to move Nearby Users">
            <span className="workspace-chat-icon"><UsersIcon /></span>
            <div className="workspace-chat-title"><p>Company LAN</p><strong>Nearby Users <small>{devices.length} online</small></strong></div>
            <button type="button" className="workspace-chat-minimize" onPointerDown={(event) => event.stopPropagation()} onClick={() => setIsOpen(false)} aria-label="Minimize Nearby Users">−</button>
          </header>
          <div className="workspace-chat-users" aria-live="polite">
            {sortedUsers.length === 0 ? <p>No colleagues are online yet.</p> : sortedUsers.map((user) => {
              const activeChat = chats.find((item) => item.peerId === user.id && item.status === "active");
              const pendingChat = chats.find((item) => item.peerId === user.id && item.status === "pending");
              const latestMessage = activeChat?.messages.at(-1)?.text;
              const hasIncomingRequest = pendingChat?.direction === "incoming";
              const needsAttention = Boolean((activeChat && unreadChatIds.includes(activeChat.id)) || hasIncomingRequest);
              return <button type="button" className={`workspace-chat-user${needsAttention ? " has-unread" : ""}`} key={user.id} onClick={() => void openUser(user.id)}>
                <span className="workspace-chat-avatar">{avatarInitial(user.displayName)}</span>
                <span><strong>{user.displayName}</strong><small>{latestMessage || (hasIncomingRequest ? "Chat request" : user.displayName === "Guest" ? `Guest • ${user.deviceName}` : user.deviceName)}</small></span>
                <i aria-label={needsAttention ? "New chat item" : "Online"} className={needsAttention ? "is-unread" : ""} />
              </button>;
            })}
          </div>
          <Link className="workspace-chat-share" to="/">Share a file from Home</Link>
        </>
      )}
    </aside>
  ) : (
    <button type="button" className="workspace-chat-launcher" onClick={() => setIsOpen(true)} aria-label="Open Nearby Users">
      <UsersIcon /><span>Nearby Users</span>{newItemCount > 0 && <i aria-label={`${newItemCount} new chat item${newItemCount === 1 ? "" : "s"}`} />}
    </button>
  );
}
