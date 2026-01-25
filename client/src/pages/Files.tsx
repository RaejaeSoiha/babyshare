// Files list page for users and admin.
import { useEffect, useState } from "react";

type FileItem = {
  file: string;
  original?: string;
  label?: string;
  uploaded?: number | null;
  expires?: number | null;
  passwordProtected: boolean;
};

type AdminPayload = {
  isAdmin: true;
  users: { username: string; files: FileItem[] }[];
};

type UserPayload = {
  isAdmin: false;
  user: string;
  files: FileItem[];
};

type Payload = AdminPayload | UserPayload;

export default function Files() {
  const [data, setData] = useState<Payload | null>(null);

  // Load file metadata from the API.
  useEffect(() => {
    fetch("/api/files")
      .then((res) => {
        if (res.status === 401) {
          window.location.href = "/login";
          return null;
        }
        return res.json();
      })
      .then((payload) => {
        if (payload) setData(payload);
      });
  }, []);

  if (!data) {
    return (
      <div className="page auth">
        <div className="auth-card">
          <h1>Loading...</h1>
        </div>
      </div>
    );
  }

  const renderFile = (item: FileItem, username: string) => {
    const name = item.label || item.original || item.file;
    const base = `/secure-download/${username}/${item.file}`;
    return (
      <div className="file-row" key={`${username}-${item.file}`}>
        <div>
          <strong>{name}</strong>
          {item.label && item.original && <div className="muted">({item.original})</div>}
          <div className="meta">
            {item.passwordProtected ? "?? Password protected" : "? Open access"}
          </div>
        </div>
        <div className="file-actions">
          <a className="btn btn-register" href={`${base}?action=preview`}>Review</a>
          <a className="btn btn-login" href={`${base}?action=download`}>Download</a>
          <a className="btn btn-danger" href={`/delete/${username}/${item.file}`}>Delete</a>
        </div>
      </div>
    );
  };

  return (
    <div className="page auth">
      <div className="auth-card wide">
        <h1>{data.isAdmin ? "All Files" : "My Files"}</h1>
        <div className="file-list">
          {data.isAdmin
            ? data.users.map((u) => (
                <div key={u.username} className="user-block">
                  <h2>{u.username}</h2>
                  {u.files.length === 0 ? (
                    <p className="muted">No files.</p>
                  ) : (
                    u.files.map((f) => renderFile(f, u.username))
                  )}
                </div>
              ))
            : data.files.length === 0
            ? <p className="muted">No files uploaded yet.</p>
            : data.files.map((f) => renderFile(f, data.user))}
        </div>
        <div className="cta-row">
          <a className="btn btn-register" href="/dashboard">Back</a>
        </div>
      </div>
    </div>
  );
}
