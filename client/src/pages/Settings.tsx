import { useMemo, useState } from "react";
import { Link } from "react-router-dom";
import { useLanTransfers } from "../components/LanTransfers";
import LogoutButton from "../components/LogoutButton";

type TrustedDevice = { id: string; name: string; platform: string; trustedAt: number };
const TRUSTED_DEVICES_KEY = "babyshare.trusted-devices";

function readTrustedDevices(): TrustedDevice[] {
  try {
    const value = JSON.parse(localStorage.getItem(TRUSTED_DEVICES_KEY) || "[]");
    return Array.isArray(value) ? value.filter((item): item is TrustedDevice => item && typeof item.id === "string" && typeof item.name === "string").slice(0, 50) : [];
  } catch { return []; }
}

export default function Settings() {
  const { currentDevice, devices, discoverable, renameCurrentDevice, setDiscoverable, signOutCurrentDevice } = useLanTransfers();
  const [name, setName] = useState(currentDevice.name);
  const [trusted, setTrusted] = useState<TrustedDevice[]>(readTrustedDevices);
  const [saved, setSaved] = useState(false);

  const onlineIds = useMemo(() => new Set(devices.map((device) => device.id)), [devices]);
  const saveTrusted = (next: TrustedDevice[]) => { setTrusted(next); localStorage.setItem(TRUSTED_DEVICES_KEY, JSON.stringify(next)); };
  const trust = (id: string) => {
    const device = devices.find((candidate) => candidate.id === id);
    if (!device || trusted.some((item) => item.id === id)) return;
    saveTrusted([...trusted, { id, name: device.displayName, platform: device.platform, trustedAt: Date.now() }]);
  };
  const forget = (id: string) => saveTrusted(trusted.filter((device) => device.id !== id));

  return <main className="page settings-page"><section className="dashboard-shell settings-shell">
    <header className="dashboard-header dashboard-topbar"><Link className="dashboard-brand" to="/" aria-label="BabyShare home"><span className="dashboard-brand-mark">ϟ</span><span>BabyShare</span></Link><div className="dashboard-actions"><Link className="btn btn-ghost" to="/dashboard">Workspace</Link><Link className="btn btn-ghost" to="/files">History</Link><LogoutButton /></div></header>
    <section className="dashboard-welcome dashboard-card"><div><p className="eyebrow">Privacy and devices</p><h1>Control how this browser appears.</h1><p>These preferences affect local discovery and trusted-device shortcuts. File content is never included.</p></div></section>
    <div className="settings-grid">
      <section className="dashboard-card settings-card"><p className="eyebrow">My device</p><h2>{currentDevice.platform}</h2><label>Device name<input value={name} maxLength={80} onChange={(event) => { setName(event.target.value); setSaved(false); }} /></label><div className="direct-send-actions"><button className="btn btn-register" type="button" onClick={() => { renameCurrentDevice(name); setSaved(true); }}>Save name</button>{saved && <span className="settings-saved">Saved</span>}</div><p className="settings-device-id">Browser ID: {currentDevice.id.slice(0, 12)}…</p><button className="lan-decline" type="button" onClick={signOutCurrentDevice}>Forget this browser</button></section>
      <section className="dashboard-card settings-card"><p className="eyebrow">Discovery privacy</p><h2>Nearby visibility</h2><label className="settings-switch"><input type="checkbox" checked={discoverable} onChange={(event) => setDiscoverable(event.target.checked)} /><span>Appear to nearby BabyShare users</span></label><p>Turn this off to stop sending presence heartbeats. Existing peers disappear automatically after the short presence timeout.</p></section>
      <section className="dashboard-card settings-card settings-card-wide"><p className="eyebrow">Trusted contacts</p><h2>Trusted devices</h2><p>Trust is stored only in this browser. It does not bypass file-acceptance consent.</p><div className="trusted-device-list">{trusted.length ? trusted.map((device) => <div className="trusted-device" key={device.id}><div><strong>{device.name}</strong><span>{device.platform} · {onlineIds.has(device.id) ? "Online now" : "Offline"}</span></div><button className="dashboard-text-button" type="button" onClick={() => forget(device.id)}>Forget</button></div>) : <p>No trusted devices yet.</p>}</div>
        {devices.filter((device) => !trusted.some((item) => item.id === device.id)).length > 0 && <div className="trusted-add-row"><label>Add an online device<select defaultValue="" onChange={(event) => { trust(event.target.value); event.currentTarget.value = ""; }}><option value="" disabled>Select a device</option>{devices.filter((device) => !trusted.some((item) => item.id === device.id)).map((device) => <option value={device.id} key={device.id}>{device.displayName} · {device.platform}</option>)}</select></label></div>}
      </section>
    </div>
  </section></main>;
}
