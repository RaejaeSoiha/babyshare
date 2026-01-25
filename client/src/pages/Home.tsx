// Marketing landing page.
export default function Home() {
  return (
    <div className="page home">
      <main className="hero">
        <div className="hero-title">
          <span className="hero-icon" aria-hidden="true">
            <svg viewBox="0 0 24 24" role="img">
              <path
                d="M14.7 3.2c-2.7.7-5.1 2.2-6.9 4.1L4 11l3 3 3.7-3.7c2-1.9 3.5-4.2 4.3-7.1.2-.8-.6-1.6-1.3-1.3z"
                fill="currentColor"
              />
              <path
                d="M6.5 17.5l-2.5 3.8 3.8-2.5 1.2-1.2-2.5-2.5-1.2 1.2z"
                fill="currentColor"
              />
              <circle cx="13.5" cy="7.5" r="1.5" fill="#0b0f16" />
            </svg>
          </span>
          <h1>Baby Share</h1>
        </div>
        <p className="tagline">Fast. Private. Encrypted.</p>

        <div className="badges">
          <span className="badge badge-encrypted">
            <svg viewBox="0 0 24 24" role="img" aria-hidden="true">
              <path
                d="M7 10V8a5 5 0 0 1 10 0v2h1a1 1 0 0 1 1 1v8a1 1 0 0 1-1 1H6a1 1 0 0 1-1-1v-8a1 1 0 0 1 1-1h1zm2 0h6V8a3 3 0 0 0-6 0v2z"
                fill="currentColor"
              />
            </svg>
            Encrypted
          </span>
          <span className="badge badge-expiry">
            <svg viewBox="0 0 24 24" role="img" aria-hidden="true">
              <path
                d="M6 2a1 1 0 0 1 1 1v1h10V3a1 1 0 1 1 2 0v1h1a1 1 0 0 1 1 1v3H3V5a1 1 0 0 1 1-1h1V3a1 1 0 0 1 1-1zm-3 8h20v9a1 1 0 0 1-1 1H4a1 1 0 0 1-1-1v-9zm9 2v5l4-2.5-4-2.5z"
                fill="currentColor"
              />
            </svg>
            30d retention
          </span>
        </div>

        <div className="feature-grid">
          <div className="feature-card">
            <span className="feature-icon" aria-hidden="true">
              <svg viewBox="0 0 24 24" role="img">
                <path
                  d="M13 2L3 14h7l-1 8 12-14h-7l-1-6z"
                  fill="currentColor"
                />
              </svg>
            </span>
            <div className="feature-text">LAN Speed Performance</div>
          </div>
          <div className="feature-card">
            <span className="feature-icon" aria-hidden="true">
              <svg viewBox="0 0 24 24" role="img">
                <path
                  d="M12 2a10 10 0 1 0 0 20 10 10 0 0 0 0-20zm6.9 9h-3.2a15 15 0 0 0-1.3-5 8.04 8.04 0 0 1 4.5 5zm-6.9-7c1.1 1.4 2 3.4 2.4 5H9.6c.4-1.6 1.3-3.6 2.4-5zM5.6 6a15 15 0 0 0-1.3 5H1.1a8.04 8.04 0 0 1 4.5-5zM1.1 13h3.2a15 15 0 0 0 1.3 5 8.04 8.04 0 0 1-4.5-5zm10.9 7c-1.1-1.4-2-3.4-2.4-5h4.8c-.4 1.6-1.3 3.6-2.4 5zm2.4-7H9.6a14.1 14.1 0 0 1 0-2h4.8a14.1 14.1 0 0 1 0 2zm4.1 0a8.04 8.04 0 0 1-4.5 5 15 15 0 0 0 1.3-5h3.2z"
                  fill="currentColor"
                />
              </svg>
            </span>
            <div className="feature-text">Private & Local Only</div>
          </div>
          <div className="feature-card">
            <span className="feature-icon" aria-hidden="true">
              <svg viewBox="0 0 24 24" role="img">
                <path
                  d="M3 6a2 2 0 0 1 2-2h4l2 2h8a2 2 0 0 1 2 2v10a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V6z"
                  fill="currentColor"
                />
              </svg>
            </span>
            <div className="feature-text">Easy File Management</div>
          </div>
        </div>

        <div className="cta-row">
          <a className="btn btn-login" href="/login">Login</a>
          <a className="btn btn-register" href="/register">Register</a>
          <a className="btn btn-guest" href="/guest-upload">Upload as Guest</a>
        </div>

        <div className="tip">Tip: This is a private LAN-only file sharing service.</div>
      </main>
    </div>
  );
}
