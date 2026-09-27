import { apiUrl } from "../lib/api";

function LightningMark() {
  return (
    <svg viewBox="0 0 24 24" aria-hidden="true">
      <path d="M13.2 1.8 4.6 13h6.1l-.9 9.2L19.4 11h-6.1l-.1-9.2Z" fill="currentColor" />
    </svg>
  );
}

function ShieldIcon() {
  return (
    <svg viewBox="0 0 24 24" aria-hidden="true">
      <path d="M12 3 5 6v5.3c0 4.4 3 7.9 7 9.7 4-1.8 7-5.3 7-9.7V6l-7-3Zm-3.2 9 2.1 2.1 4.4-4.4" fill="none" stroke="currentColor" strokeLinecap="round" strokeLinejoin="round" strokeWidth="1.7" />
    </svg>
  );
}

function ArrowIcon() {
  return <svg viewBox="0 0 24 24" aria-hidden="true"><path d="M5 12h13m-5-5 5 5-5 5" fill="none" stroke="currentColor" strokeLinecap="round" strokeLinejoin="round" strokeWidth="1.8" /></svg>;
}

export default function Login() {
  return (
    <div className="page auth login-page">
      <header className="login-header">
        <a className="login-brand" href="/" aria-label="BabyShare home">
          <span className="login-brand-mark"><LightningMark /></span>
          <span>BabyShare</span>
        </a>
        <a className="login-home-link" href="/">Back to home</a>
      </header>

      <main className="login-shell">
        <section className="login-intro" aria-labelledby="login-page-title">
          <p className="login-eyebrow">PRIVATE WORKSPACE</p>
          <h1 id="login-page-title">Everything you share, in reach.</h1>
          <p>Sign in to manage your files, trusted links, and private collaboration.</p>
          <div className="login-trust" aria-label="BabyShare benefits">
            <span><ShieldIcon />Private by design</span>
            <span><i aria-hidden="true" />Secure sharing</span>
          </div>
        </section>

        <section className="login-card" aria-labelledby="sign-in-title">
          <div className="login-card-icon"><ShieldIcon /></div>
          <p className="login-card-kicker">ACCOUNT ACCESS</p>
          <h2 id="sign-in-title">Welcome back</h2>
          <p className="login-card-copy">Sign in to continue to your workspace.</p>

          <form method="POST" action={apiUrl("/login")} className="login-form">
            <label>
              <span>Username</span>
              <input name="username" minLength={3} maxLength={32} placeholder="Enter username" autoComplete="username" autoFocus required />
            </label>
            <label>
              <span>Password</span>
              <input type="password" name="password" maxLength={128} placeholder="Enter password" autoComplete="current-password" required />
            </label>
            <button type="submit" className="login-submit">Sign in <ArrowIcon /></button>
          </form>

          <div className="login-register-prompt">
            <span>New to BabyShare?</span>
            <a href="/register">Create account</a>
          </div>
        </section>
      </main>
    </div>
  );
}
