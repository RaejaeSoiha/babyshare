// Public entry point for BabyShare's direct browser-to-browser workflow.
import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { apiFetch } from "../lib/api";

export default function Home() {
  const [signedIn, setSignedIn] = useState(false);

  useEffect(() => {
    apiFetch("/api/me").then((response) => setSignedIn(response.ok)).catch(() => setSignedIn(false));
  }, []);

  return (
    <main className="page home-page">
      <section className="home-main direct-home-main">
        <header className="home-nav">
          <Link className="brand" to="/"><span className="brand-mark">ϟ</span><span>BabyShare</span></Link>
          <nav aria-label="Primary navigation"><Link to="/guest-receive">Enter pairing code</Link>{signedIn ? <Link className="btn btn-login" to="/dashboard">Open workspace</Link> : <><Link to="/login">Sign in</Link><Link className="btn btn-login" to="/register">Create account</Link></>}</nav>
        </header>
        <section className="home-hero direct-home-hero">
          <p className="eyebrow">PRIVATE DIRECT TRANSFER</p>
          <h1>Files move between <span>your devices.</span></h1>
          <p className="hero-copy">BabyShare uses encrypted WebRTC connections. The service coordinates consent, pairing, and presence — never permanent file storage.</p>
          <div className="cta-row"><Link className="btn btn-register" to={signedIn ? "/dashboard" : "/register"}>{signedIn ? "Send files" : "Create a private workspace"}</Link><Link className="btn btn-ghost" to="/guest-upload">Send with QR pairing</Link></div>
        </section>
        <section className="feature-indicators direct-home-features" aria-label="BabyShare privacy features">
          <article><span aria-hidden="true">↔</span><h2>Direct</h2><p>File bytes do not pass through BabyShare.</p></article>
          <article><span aria-hidden="true">✓</span><h2>Consent first</h2><p>Recipients approve each incoming file.</p></article>
          <article><span aria-hidden="true">⌁</span><h2>Pair anywhere</h2><p>Use nearby devices, QR, or an 8-digit code.</p></article>
        </section>
      </section>
    </main>
  );
}
