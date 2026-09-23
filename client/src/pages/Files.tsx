// Files list page for users and administrators.
import { useCallback, useEffect, useState } from "react";
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

export default function Files() {
  const [data, setData] = useState<Payload | null>(null);
  const [error, setError] = useState("");

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
    if (!window.confirm("Delete this file? This cannot be undone.")) return;
    setError("");
    try {
      const response = await apiFetch(`/api/files/${encodeURIComponent(username)}/${encodeURIComponent(file)}`, { method: "DELETE" });
      if (!response.ok) throw new Error("delete_failed");
      await loadFiles();
    } catch {
      setError("Could not delete the file. Try again.");
    }
  };

  if (!data) {
    return (
      <div className="page auth">
        <div className="auth-card">
          <h1>{error ? "Files unavailable" : "Loading..."}</h1>
          {error && <p className="error" role="alert">{error}</p>}
          {error && <button type="button" className="btn btn-login" onClick={() => void loadFiles()}>Retry</button>}
        </div>
      </div>
    );
  }

  const renderFile = (item: FileItem, username: string) => {
    const name = item.label || item.original || item.file;
    const shareUrl = apiUrl(`/secure-download/${encodeURIComponent(username)}/${encodeURIComponent(item.file)}`);
    return (
      <div className="file-row" key={`${username}-${item.file}`}>
        <div>
          <strong>{name}</strong>
          {item.label && item.original && <div className="muted">{item.original}</div>}
          <div className="meta">{item.passwordProtected ? "Password protected" : "Open access"}</div>
        </div>
        <div className="file-actions">
          <a className="btn btn-register" href={`${shareUrl}?action=preview`}>Review</a>
          <a className="btn btn-login" href={`${shareUrl}?action=download`}>Download</a>
          <button className="btn btn-danger" type="button" onClick={() => void deleteFile(username, item.file)}>Delete</button>
        </div>
      </div>
    );
  };

  return (
    <div className="page auth">
      <div className="auth-card wide">
        <h1>{data.isAdmin ? "All Files" : "My Files"}</h1>
        {error && <p className="error" role="alert">{error}</p>}
        <div className="file-list">
          {data.isAdmin
            ? data.users.map((user) => (
                <div key={user.username} className="user-block">
                  <h2>{user.username}</h2>
                  {user.files.length === 0 ? <p className="muted">No files.</p> : user.files.map((file) => renderFile(file, user.username))}
                </div>
              ))
            : data.files.length === 0
              ? <p className="muted">No files uploaded yet.</p>
              : data.files.map((file) => renderFile(file, data.user))}
        </div>
        <div className="cta-row">
          <a className="btn btn-register" href="/dashboard">Back</a>
        </div>
      </div>
    </div>
  );
}
