// File Vault: authenticated users manage their shares; administrators can manage every account's files.
import { useCallback, useEffect, useMemo, useState } from "react";
import { Link } from "react-router-dom";
import { apiFetch, apiUrl } from "../lib/api";

type FileItem = {
  expires?: number | null;
  file: string;
  label?: string;
  original?: string;
  passwordProtected: boolean;
  uploaded?: number | null;
};
type AdminPayload = { isAdmin: true; users: { files: FileItem[]; username: string }[] };
type UserPayload = { files: FileItem[]; isAdmin: false; user: string };
type Payload = AdminPayload | UserPayload;
type FileGroup = { files: FileItem[]; username: string };

function FileIcon() {
  return (
    <svg viewBox="0 0 24 24" aria-hidden="true">
      <path d="M7 3.5h6l4 4V20a1 1 0 0 1-1 1H7a1 1 0 0 1-1-1V4.5a1 1 0 0 1 1-1Zm5.5 0V8H17M9 13h6m-6 3.5h4" fill="none" stroke="currentColor" strokeLinecap="round" strokeLinejoin="round" strokeWidth="1.6" />
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

function formatDate(timestamp?: number | null) {
  if (!timestamp) return "Not available";
  return new Intl.DateTimeFormat(undefined, { day: "numeric", month: "short", year: "numeric" }).format(timestamp);
}

function expiryLabel(expires?: number | null) {
  if (!expires) return "No expiry set";
  const days = Math.max(1, Math.ceil((expires - Date.now()) / (24 * 60 * 60 * 1000)));
  return `Expires in ${days} ${days === 1 ? "day" : "days"}`;
}

function initial(username: string) {
  return username.trim().charAt(0).toUpperCase() || "U";
}

export default function Files() {
  const [data, setData] = useState<Payload | null>(null);
  const [error, setError] = useState("");
  const [query, setQuery] = useState("");
  const [copied, setCopied] = useState("");
  const [deleting, setDeleting] = useState("");

  const requestFiles = useCallback(async () => {
    const response = await apiFetch("/api/files");
    if (response.status === 401) {
      window.location.assign("/login");
      return null;
    }
    if (!response.ok) throw new Error("files_load_failed");
    return response.json() as Promise<Payload>;
  }, []);

  useEffect(() => {
    requestFiles()
      .then((payload) => payload && setData(payload))
      .catch(() => setError("Unable to load files. Refresh the page and try again."));
  }, [requestFiles]);

  const loadFiles = async () => {
    setError("");
    try {
      const payload = await requestFiles();
      if (payload) setData(payload);
    } catch {
      setError("Unable to load files. Refresh the page and try again.");
    }
  };

  const deleteFile = async (username: string, file: string) => {
    if (!window.confirm("Delete this file and its share link? This cannot be undone.")) return;
    setError("");
    setDeleting(`${username}-${file}`);
    try {
      const response = await apiFetch(`/api/files/${encodeURIComponent(username)}/${encodeURIComponent(file)}`, { method: "DELETE" });
      if (!response.ok) throw new Error("delete_failed");
      await loadFiles();
    } catch {
      setError("Could not delete the file. Try again.");
    } finally {
      setDeleting("");
    }
  };

  const copyLink = async (shareUrl: string) => {
    try {
      await navigator.clipboard.writeText(shareUrl);
      setCopied(shareUrl);
    } catch {
      setError("Could not copy the link. Select it from the preview page instead.");
    }
  };

  const logout = async () => {
    await apiFetch("/logout", { method: "POST" });
    window.location.assign("/");
  };

  const groups = useMemo<FileGroup[]>(() => {
    if (!data) return [];
    if (data.isAdmin) return [...data.users].sort((left, right) => left.username.localeCompare(right.username));
    return [{ files: data.files, username: data.user }];
  }, [data]);

  const filteredGroups = useMemo(() => {
    const needle = query.trim().toLocaleLowerCase();
    if (!needle) return groups;
    return groups
      .map((group) => ({
        ...group,
        files: group.files.filter((item) => [group.username, item.label, item.original, item.file]
          .filter(Boolean)
          .some((value) => String(value).toLocaleLowerCase().includes(needle))),
      }))
      .filter((group) => group.files.length > 0 || group.username.toLocaleLowerCase().includes(needle));
  }, [groups, query]);

  const totalFiles = groups.reduce((total, group) => total + group.files.length, 0);
  const hasMatches = filteredGroups.some((group) => group.files.length > 0);

  if (!data) {
    return (
      <div className="page auth">
        <div className="auth-card">
          <h1>{error ? "File Vault unavailable" : "Loading File Vault..."}</h1>
          {error && <p className="error" role="alert">{error}</p>}
          {error && <button type="button" className="btn btn-login" onClick={() => void loadFiles()}>Retry</button>}
        </div>
      </div>
    );
  }

  const renderFile = (item: FileItem, username: string) => {
    const name = item.label || item.original || item.file;
    const shareUrl = apiUrl(`/secure-download/${encodeURIComponent(username)}/${encodeURIComponent(item.file)}`);
    const key = `${username}-${item.file}`;
    return (
      <article className="vault-file" key={key}>
        <div className="vault-file-icon"><FileIcon /></div>
        <div className="vault-file-details">
          <div className="vault-file-title-row">
            <strong title={name}>{name}</strong>
            {item.passwordProtected && <span className="vault-protection"><ShieldIcon /> Password protected</span>}
          </div>
          {item.label && item.original && item.label !== item.original && <span className="vault-original">{item.original}</span>}
          <div className="vault-file-meta">
            <span>{expiryLabel(item.expires)}</span>
            <span>Uploaded {formatDate(item.uploaded)}</span>
          </div>
        </div>
        <div className="vault-file-actions">
          <button className="btn btn-ghost" type="button" onClick={() => void copyLink(shareUrl)}>{copied === shareUrl ? "Link copied" : "Copy link"}</button>
          <a className="btn btn-register" href={`${shareUrl}?action=preview`}>Preview</a>
          <a className="vault-download" href={`${shareUrl}?action=download`}>Download <ArrowIcon /></a>
          <button className="vault-delete" type="button" onClick={() => void deleteFile(username, item.file)} disabled={deleting === key}>{deleting === key ? "Deleting..." : "Delete"}</button>
        </div>
      </article>
    );
  };

  return (
    <main className="page vault-page">
      <section className="vault-shell">
        <header className="dashboard-header dashboard-topbar vault-topbar">
          <Link className="dashboard-brand" to="/" aria-label="BabyShare home">
            <span className="dashboard-brand-mark">ϟ</span>
            <span>BabyShare</span>
          </Link>
          <div className="dashboard-actions">
            <Link className="btn btn-ghost" to="/dashboard">Dashboard</Link>
            {data.isAdmin && <Link className="btn btn-admin" to="/admin">Admin Panel</Link>}
            <button className="dashboard-logout" type="button" onClick={() => void logout()}>Log out</button>
          </div>
        </header>

        <section className="vault-hero dashboard-card">
          <div>
            <p className="eyebrow">{data.isAdmin ? "Administrator view" : "Personal files"}</p>
            <h1>File Vault</h1>
            <p>{data.isAdmin ? "Review and manage every active BabyShare file in one protected workspace." : "Your active encrypted files and share links, all in one place."}</p>
          </div>
          <div className="vault-stats" aria-label="File Vault summary">
            <div><strong>{totalFiles}</strong><span>{totalFiles === 1 ? "Active file" : "Active files"}</span></div>
            {data.isAdmin && <div><strong>{groups.length}</strong><span>{groups.length === 1 ? "Account" : "Accounts"}</span></div>}
          </div>
        </section>

        <section className="vault-toolbar dashboard-card">
          <label className="vault-search">
            <span>Search files</span>
            <input value={query} onChange={(event) => setQuery(event.target.value)} placeholder={data.isAdmin ? "File name or account" : "File name"} />
          </label>
          <div className="vault-toolbar-actions">
            <button className="btn btn-ghost" type="button" onClick={() => void loadFiles()}>Refresh</button>
            <Link className="btn btn-guest" to="/dashboard">Upload files</Link>
          </div>
        </section>

        {error && <p className="error vault-error" role="alert">{error}</p>}

        <section className="vault-groups" aria-label="Stored files">
          {!hasMatches ? (
            <div className="vault-empty dashboard-card">
              <span className="vault-file-icon"><FileIcon /></span>
              <h2>{query ? "No matching files" : "No files in the vault yet"}</h2>
              <p>{query ? "Try a different file name or account." : "Create your first encrypted share from the dashboard."}</p>
              {!query && <Link className="btn btn-guest" to="/dashboard">Upload files</Link>}
            </div>
          ) : filteredGroups.map((group) => (
            <section className="vault-group dashboard-card" key={group.username}>
              <header className="vault-group-header">
                <div className="vault-avatar" aria-hidden="true">{initial(group.username)}</div>
                <div>
                  <p className="eyebrow">{data.isAdmin ? "Account" : "Your files"}</p>
                  <h2>{group.username}</h2>
                </div>
                <span className="vault-count">{group.files.length} {group.files.length === 1 ? "file" : "files"}</span>
              </header>
              {group.files.length > 0 ? <div className="vault-file-list">{group.files.map((file) => renderFile(file, group.username))}</div> : <p className="vault-no-files">No matching files for this account.</p>}
            </section>
          ))}
        </section>
      </section>
    </main>
  );
}
