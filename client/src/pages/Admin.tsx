// Admin panel for user management and stats.
import { useEffect, useState } from "react";

type Overview = { usersCount: number; guestsCount: number };
type UserRow = { username: string; fileCount: number };

export default function Admin() {
  const [overview, setOverview] = useState<Overview | null>(null);
  const [users, setUsers] = useState<UserRow[]>([]);
  const [error, setError] = useState("");
  const [newUser, setNewUser] = useState("");
  const [newPass, setNewPass] = useState("");

  // Fetch overview + user list.
  const loadAll = () => {
    fetch("/api/admin/overview")
      .then((res) => {
        if (res.status === 401 || res.status === 403) {
          window.location.href = "/dashboard";
          return null;
        }
        return res.json();
      })
      .then((data) => data && setOverview(data));

    fetch("/api/admin/users")
      .then((res) => res.json())
      .then((data) => setUsers(data.users || []));
  };

  useEffect(() => {
    loadAll();
  }, []);

  const addUser = async (e: React.FormEvent) => {
    e.preventDefault();
    setError("");
    const res = await fetch("/api/admin/users", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ username: newUser, password: newPass }),
    });
    if (!res.ok) {
      setError("Failed to add user.");
      return;
    }
    setNewUser("");
    setNewPass("");
    loadAll();
  };

  const resetUser = async (username: string) => {
    const res = await fetch(`/api/admin/users/${username}/reset`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({}),
    });
    if (!res.ok) {
      setError("Failed to reset user.");
      return;
    }
    const data = await res.json();
    alert(`New password for ${username}: ${data.newPassword}`);
  };

  const removeUser = async (username: string) => {
    if (!confirm(`Delete user ${username}?`)) return;
    const res = await fetch(`/api/admin/users/${username}`, { method: "DELETE" });
    if (!res.ok) {
      setError("Failed to delete user.");
      return;
    }
    loadAll();
  };

  return (
    <div className="page auth">
      <div className="auth-card wide">
        <h1>Admin Panel</h1>
        {overview && (
          <div className="stats">
            Users: {overview.usersCount} | Guests active: {overview.guestsCount}
          </div>
        )}

        <form className="form" onSubmit={addUser}>
          <label>
            New username
            <input value={newUser} onChange={(e) => setNewUser(e.target.value)} required />
          </label>
          <label>
            Password
            <input type="password" value={newPass} onChange={(e) => setNewPass(e.target.value)} required />
          </label>
          <button className="btn btn-login" type="submit">Add User</button>
        </form>

        {error && <p className="error">{error}</p>}

        <div className="user-table">
          {users.map((u) => (
            <div key={u.username} className="user-row">
              <div>
                <strong>{u.username}</strong>
                <div className="muted">Files: {u.fileCount}</div>
              </div>
              <div className="file-actions">
                {u.username !== "admin" ? (
                  <>
                    <button className="btn btn-register" type="button" onClick={() => resetUser(u.username)}>Reset</button>
                    <button className="btn btn-danger" type="button" onClick={() => removeUser(u.username)}>Delete</button>
                  </>
                ) : (
                  <span className="muted">Protected</span>
                )}
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
