import { useState } from "react";
import { apiFetch } from "../lib/api";

export default function LogoutButton() {
  const [busy, setBusy] = useState(false);

  const logout = async () => {
    if (busy) return;
    setBusy(true);
    try {
      await apiFetch("/logout", { method: "POST" });
    } finally {
      window.location.assign("/");
    }
  };

  return <button className="dashboard-logout" type="button" disabled={busy} onClick={() => void logout()}>{busy ? "Logging out…" : "Log out"}</button>;
}
