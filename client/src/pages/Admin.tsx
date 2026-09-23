// Admin panel for user management and storage stats.
import { useCallback, useEffect, useState } from "react";
import { apiFetch } from "../lib/api";

type Overview = { guestsCount: number; usersCount: number };
type UserRow = { fileCount: number; username: string };

export default function Admin() {
  const [overview, setOverview] = useState<Overview | null>(null);
  const [users, setUsers] = useState<UserRow[]>([]);
  const [error, setError] = useState("");
  const [newUser, setNewUser] = useState("");
  const [newPass, setNewPass] = useState("");

  const requestAdminData = useCallback(async () => {
    const [overviewResponse, usersResponse] = await Promise.all([
      apiFetch("/api/admin/overview"),
      apiFetch("/api/admin/users"),
    ]);
    if (overviewResponse.status === 401 || overviewResponse.status === 403 || usersResponse.status === 401 || usersResponse.status === 403) {
      window.location.assign("/dashboard");
      return null;
    }
    if (!overviewResponse.ok || !usersResponse.ok) throw new Error("admin_load_failed");
    return {
      overview: await overviewResponse.json() as Overview,
      users: (await usersResponse.json() as { users: UserRow[] }).users || [],
    };
  }, []);

  useEffect(() => {
    requestAdminData()
      .then((data) => {
        if (data) {
          setOverview(data.overview);
          setUsers(data.users);
        }
      })
      .catch(() => setError("Unable to load administration data."));
  }, [requestAdminData]);

  const loadAll = async () => {
    setError("");
    try {
      const data = await requestAdminData();
      if (data) {
        setOverview(data.overview);
        setUsers(data.users);
      }
    } catch {
      setError("Unable to load administration data.");
    }
  };

  const addUser = async (event: React.FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    setError("");
    const response = await apiFetch("/api/admin/users", {
      body: JSON.stringify({ password: newPass, username: newUser }),
      headers: { "Content-Type": "application/json" },
      method: "POST",
    });
    if (!response.ok) {
      setError("Could not add the user. Usernames need 3-32 characters and passwords need 12+ characters.");
      return;
    }
    setNewUser("");
    setNewPass("");
    await loadAll();
  };

  const resetUser = async (username: string) => {
    const newPassword = window.prompt(`Enter a new password for ${username} (12+ characters):`);
    if (!newPassword) return;
    setError("");
    const response = await apiFetch(`/api/admin/users/${encodeURIComponent(username)}/reset`, {
      body: JSON.stringify({ newPassword }),
      headers: { "Content-Type": "application/json" },
      method: "POST",
    });
    if (!response.ok) {
      setError("Could not reset the password. It must contain at least 12 characters.");
    }
  };

  const removeUser = async (username: string) => {
    if (!window.confirm(`Delete ${username} and all of their stored files? This cannot be undone.`)) return;
    setError("");
    const response = await apiFetch(`/api/admin/users/${encodeURIComponent(username)}`, { method: "DELETE" });
    if (!response.ok) {
      setError("Could not delete the user.");
      return;
    }
    await loadAll();
  };

  return (
    <div className="page auth">
      <div className="auth-card wide">
        <h1>Admin Panel</h1>
        {overview && <div className="stats">Users: {overview.usersCount} | Guest shares: {overview.guestsCount}</div>}

        <form className="form" onSubmit={addUser}>
          <label>
            New username
            <input value={newUser} minLength={3} maxLength={32} onChange={(event) => setNewUser(event.target.value)} required />
          </label>
          <label>
            Password
            <input type="password" value={newPass} minLength={12} maxLength={128} onChange={(event) => setNewPass(event.target.value)} required />
          </label>
          <button className="btn btn-login" type="submit">Add User</button>
        </form>

        {error && <p className="error" role="alert">{error}</p>}
        <div className="user-table">
          {users.map((user) => (
            <div key={user.username} className="user-row">
              <div>
                <strong>{user.username}</strong>
                <div className="muted">Files: {user.fileCount}</div>
              </div>
              <div className="file-actions">
                {user.username !== "admin" ? (
                  <>
                    <button className="btn btn-register" type="button" onClick={() => void resetUser(user.username)}>Reset password</button>
                    <button className="btn btn-danger" type="button" onClick={() => void removeUser(user.username)}>Delete</button>
                  </>
                ) : <span className="muted">Protected</span>}
              </div>
            </div>
          ))}
        </div>

        <div className="cta-row">
          <a className="btn btn-register" href="/dashboard">Back</a>
        </div>
      </div>
    </div>
  );
}
