// Administration console for user lifecycle and direct-transfer workspace status.
import { useCallback, useEffect, useMemo, useState } from "react";
import { Link } from "react-router-dom";
import LogoutButton from "../components/LogoutButton";
import { apiFetch } from "../lib/api";

type Overview = { guestsCount: number; usersCount: number };
type UserRow = { fileCount: number; username: string };

function UsersIcon() {
  return (
    <svg viewBox="0 0 24 24" aria-hidden="true">
      <path d="M16.5 19v-1.1c0-2-2-3.6-4.5-3.6s-4.5 1.6-4.5 3.6V19m12.5-1v-.7c0-1.6-1.1-3-2.8-3.5M6.8 13.8C5.1 14.3 4 15.7 4 17.3v.7M12 11.2a3.2 3.2 0 1 0 0-6.4 3.2 3.2 0 0 0 0 6.4Zm5.3-1.1a2.5 2.5 0 1 0 0-5M6.7 10.1a2.5 2.5 0 1 1 0-5" fill="none" stroke="currentColor" strokeLinecap="round" strokeLinejoin="round" strokeWidth="1.6" />
    </svg>
  );
}

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

function avatarInitial(name: string) {
  return name.trim().charAt(0).toUpperCase() || "U";
}

export default function Admin() {
  const [overview, setOverview] = useState<Overview | null>(null);
  const [users, setUsers] = useState<UserRow[]>([]);
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");
  const [newUser, setNewUser] = useState("");
  const [newPass, setNewPass] = useState("");
  const [query, setQuery] = useState("");
  const [resetTarget, setResetTarget] = useState<UserRow | null>(null);
  const [resetPassword, setResetPassword] = useState("");
  const [busyAction, setBusyAction] = useState("");

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

  const loadAll = useCallback(async () => {
    setError("");
    try {
      const data = await requestAdminData();
      if (data) {
        setOverview(data.overview);
        setUsers(data.users);
      }
    } catch {
      setError("Unable to load administration data. Refresh and try again.");
    }
  }, [requestAdminData]);

  useEffect(() => {
    requestAdminData()
      .then((data) => {
        if (data) {
          setOverview(data.overview);
          setUsers(data.users);
        }
      })
      .catch(() => setError("Unable to load administration data. Refresh and try again."));
  }, [requestAdminData]);

  const addUser = async (event: React.FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    setError("");
    setNotice("");
    setBusyAction("create");
    try {
      const response = await apiFetch("/api/admin/users", {
        body: JSON.stringify({ password: newPass, username: newUser }),
        headers: { "Content-Type": "application/json" },
        method: "POST",
      });
      if (!response.ok) {
        const payload = await response.json().catch(() => ({})) as { error?: string };
        if (payload.error === "user_exists") throw new Error("user_exists");
        throw new Error("invalid_account");
      }
      const createdUser = newUser.trim();
      setNewUser("");
      setNewPass("");
      setNotice(`${createdUser} is ready to use BabyShare.`);
      await loadAll();
    } catch (createError) {
      setError(createError instanceof Error && createError.message === "user_exists"
        ? "That username is already in use."
        : "Use a 3–32 character username and a password of at least 4 characters.");
    } finally {
      setBusyAction("");
    }
  };

  const resetUser = async (event: React.FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    if (!resetTarget) return;
    setError("");
    setNotice("");
    setBusyAction(`reset-${resetTarget.username}`);
    try {
      const response = await apiFetch(`/api/admin/users/${encodeURIComponent(resetTarget.username)}/reset`, {
        body: JSON.stringify({ newPassword: resetPassword }),
        headers: { "Content-Type": "application/json" },
        method: "POST",
      });
      if (!response.ok) throw new Error("reset_failed");
      setNotice(`Password reset for ${resetTarget.username}.`);
      setResetPassword("");
      setResetTarget(null);
    } catch {
      setError("Password reset failed. Use at least 4 characters and try again.");
    } finally {
      setBusyAction("");
    }
  };

  const removeUser = async (user: UserRow) => {
    if (!window.confirm(`Delete ${user.username} and all ${user.fileCount} stored ${user.fileCount === 1 ? "file" : "files"}? This cannot be undone.`)) return;
    setError("");
    setNotice("");
    setBusyAction(`delete-${user.username}`);
    try {
      const response = await apiFetch(`/api/admin/users/${encodeURIComponent(user.username)}`, { method: "DELETE" });
      if (!response.ok) throw new Error("delete_failed");
      setNotice(`${user.username} and their files were removed.`);
      await loadAll();
    } catch {
      setError("Could not delete the user. Try again.");
    } finally {
      setBusyAction("");
    }
  };

  const filteredUsers = useMemo(() => {
    const needle = query.trim().toLocaleLowerCase();
    return [...users]
      .filter((user) => !needle || user.username.toLocaleLowerCase().includes(needle))
      .sort((left, right) => {
        if (left.username === "admin") return -1;
        if (right.username === "admin") return 1;
        return left.username.localeCompare(right.username);
      });
  }, [query, users]);

  return (
    <main className="page admin-page">
      <section className="admin-shell">
        <header className="dashboard-header dashboard-topbar admin-topbar">
          <Link className="dashboard-brand" to="/" aria-label="BabyShare home">
            <span className="dashboard-brand-mark">ϟ</span>
            <span>BabyShare</span>
          </Link>
          <div className="dashboard-actions">
            <Link className="btn btn-ghost" to="/dashboard">Dashboard</Link>
            <Link className="btn btn-ghost" to="/files">Transfer history</Link>
            <LogoutButton />
          </div>
        </header>

        <section className="admin-hero dashboard-card">
          <div>
            <p className="eyebrow">BabyShare control center</p>
            <h1>Administration, <span>made clear.</span></h1>
            <p>Manage accounts for your private direct-sharing workspace. BabyShare does not retain uploaded files.</p>
          </div>
          <div className="admin-health" aria-label="System status">
            <span className="admin-health-dot" />
            <div><span>Service status</span><strong>Online and protected</strong></div>
          </div>
        </section>

        <section className="admin-metrics" aria-label="Administrative summary">
          <article className="admin-metric dashboard-card">
            <span className="admin-metric-icon"><UsersIcon /></span>
            <div><strong>{overview?.usersCount ?? "—"}</strong><span>Accounts</span></div>
          </article>
          <article className="admin-metric dashboard-card">
            <span className="admin-metric-icon files"><FileIcon /></span>
            <div><strong>0</strong><span>Stored files</span></div>
          </article>
          <article className="admin-metric dashboard-card">
            <span className="admin-metric-icon guests"><ShieldIcon /></span>
            <div><strong>{overview?.guestsCount ?? "—"}</strong><span>Guest shares</span></div>
          </article>
        </section>

        <div className="admin-workspace">
          <section className="dashboard-card admin-create-card">
            <div className="admin-card-heading">
              <span className="admin-metric-icon"><UsersIcon /></span>
              <div><p className="eyebrow">Account provisioning</p><h2>Create a user</h2></div>
            </div>
            <p className="admin-card-copy">New users receive their own encrypted workspace and can immediately create secure share links.</p>
            <form className="admin-create-form" onSubmit={(event) => void addUser(event)}>
              <label>
                Username
                <input value={newUser} minLength={3} maxLength={32} onChange={(event) => setNewUser(event.target.value)} placeholder="e.g. alex" autoComplete="off" required />
              </label>
              <label>
                Temporary password
                <input type="password" value={newPass} minLength={4} maxLength={128} onChange={(event) => setNewPass(event.target.value)} placeholder="4+ characters" autoComplete="new-password" required />
              </label>
              <button className="btn btn-guest admin-create-button" type="submit" disabled={busyAction === "create"}>{busyAction === "create" ? "Creating user..." : "Create secure account"}<ArrowIcon /></button>
            </form>
            <p className="admin-form-note"><ShieldIcon /> Passwords are stored securely and never shown again.</p>
          </section>

          <section className="dashboard-card admin-users-card">
            <header className="admin-users-header">
              <div><p className="eyebrow">Account directory</p><h2>Users</h2></div>
              <button className="btn btn-ghost" type="button" onClick={() => void loadAll()}>Refresh</button>
            </header>
            <label className="admin-search">
              <span>Search accounts</span>
              <input value={query} onChange={(event) => setQuery(event.target.value)} placeholder="Find a username" />
            </label>
            {error && <p className="error admin-message" role="alert">{error}</p>}
            {notice && <p className="admin-notice" role="status">{notice}</p>}
            <div className="admin-user-list">
              {filteredUsers.length === 0 ? <p className="admin-empty">No accounts match that search.</p> : filteredUsers.map((user) => {
                const protectedAdmin = user.username === "admin";
                return (
                  <article className="admin-user-row" key={user.username}>
                    <div className={`admin-user-avatar${protectedAdmin ? " protected" : ""}`}>{avatarInitial(user.username)}</div>
                    <div className="admin-user-details">
                      <div className="admin-user-name"><strong>{user.username}</strong>{protectedAdmin && <span><ShieldIcon /> Primary administrator</span>}</div>
                      <small>{user.fileCount} {user.fileCount === 1 ? "stored file" : "stored files"}</small>
                    </div>
                    <div className="admin-user-actions">
                      {protectedAdmin ? <span className="admin-protected">Protected account</span> : (
                        <>
                          <button className="btn btn-register" type="button" onClick={() => { setResetTarget(user); setResetPassword(""); setError(""); }}>Reset password</button>
                          <button className="admin-remove" type="button" onClick={() => void removeUser(user)} disabled={busyAction === `delete-${user.username}`}>{busyAction === `delete-${user.username}` ? "Deleting..." : "Delete"}</button>
                        </>
                      )}
                    </div>
                  </article>
                );
              })}
            </div>
          </section>
        </div>
      </section>

      {resetTarget && (
        <div className="admin-modal-backdrop" role="presentation" onMouseDown={() => setResetTarget(null)}>
          <section className="admin-reset-modal dashboard-card" role="dialog" aria-modal="true" aria-labelledby="reset-password-title" onMouseDown={(event) => event.stopPropagation()}>
            <button className="admin-modal-close" type="button" onClick={() => setResetTarget(null)} aria-label="Close password reset">×</button>
            <span className="admin-metric-icon"><ShieldIcon /></span>
            <p className="eyebrow">Account recovery</p>
            <h2 id="reset-password-title">Reset {resetTarget.username}&apos;s password</h2>
            <p>Set a new temporary password. The user will need this value to sign in.</p>
            <form onSubmit={(event) => void resetUser(event)}>
              <label>
                New password
                <input type="password" value={resetPassword} minLength={4} maxLength={128} onChange={(event) => setResetPassword(event.target.value)} placeholder="4+ characters" autoComplete="new-password" autoFocus required />
              </label>
              <div className="admin-modal-actions">
                <button className="btn btn-ghost" type="button" onClick={() => setResetTarget(null)}>Cancel</button>
                <button className="btn btn-guest" type="submit" disabled={busyAction === `reset-${resetTarget.username}`}>{busyAction === `reset-${resetTarget.username}` ? "Resetting..." : "Reset password"}</button>
              </div>
            </form>
          </section>
        </div>
      )}
    </main>
  );
}
