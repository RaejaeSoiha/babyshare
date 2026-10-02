import { apiUrl } from "../lib/api";

function LightningMark() {
  return <svg viewBox="0 0 24 24" aria-hidden="true"><path d="M13.2 1.8 4.6 13h6.1l-.9 9.2L19.4 11h-6.1l-.1-9.2Z" fill="currentColor" /></svg>;
}

function ShieldIcon() {
  return <svg viewBox="0 0 24 24" aria-hidden="true"><path d="M12 3 5 6v5.3c0 4.4 3 7.9 7 9.7 4-1.8 7-5.3 7-9.7V6l-7-3Zm-3.2 9 2.1 2.1 4.4-4.4" fill="none" stroke="currentColor" strokeLinecap="round" strokeLinejoin="round" strokeWidth="1.7" /></svg>;
}

function UserPlusIcon() {
  return <svg viewBox="0 0 24 24" aria-hidden="true"><path d="M15.5 20v-1.3a4.2 4.2 0 0 0-4.2-4.2H7.7a4.2 4.2 0 0 0-4.2 4.2V20m6-9.2a3.4 3.4 0 1 0 0-6.8 3.4 3.4 0 0 0 0 6.8ZM18 8v6m-3-3h6" fill="none" stroke="currentColor" strokeLinecap="round" strokeLinejoin="round" strokeWidth="1.7" /></svg>;
}

function ArrowIcon() {
  return <svg viewBox="0 0 24 24" aria-hidden="true"><path d="M5 12h13m-5-5 5 5-5 5" fill="none" stroke="currentColor" strokeLinecap="round" strokeLinejoin="round" strokeWidth="1.8" /></svg>;
}

export default function Register() {
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
        <section className="login-intro" aria-labelledby="register-page-title">
          <p className="login-eyebrow">PRIVATE WORKSPACE</p>
          <h1 id="register-page-title">Share directly.<br />Stay in control.</h1>
          <p>Create a workspace for private, browser-to-browser sharing with people nearby.</p>
          <div className="login-trust" aria-label="BabyShare benefits">
            <span><ShieldIcon />Private by design</span>
            <span><i aria-hidden="true" />No server file copies</span>
          </div>
        </section>

        <section className="login-card" aria-labelledby="create-account-title">
          <div className="login-card-icon"><UserPlusIcon /></div>
          <p className="login-card-kicker">CREATE ACCOUNT</p>
          <h2 id="create-account-title">Start your workspace</h2>
          <p className="login-card-copy">Choose a username and password to continue.</p>

          <form method="POST" action={apiUrl("/register")} className="login-form">
            <label>
              <span>Username</span>
              <input name="username" minLength={3} maxLength={32} pattern="[A-Za-z0-9][A-Za-z0-9_-]{2,31}" placeholder="Choose a username" autoComplete="username" autoFocus required />
            </label>
            <label>
              <span>Password</span>
              <input type="password" name="password" minLength={4} maxLength={128} placeholder="Create a 4+ character password" autoComplete="new-password" required />
            </label>
            <button type="submit" className="login-submit">Create account <ArrowIcon /></button>
          </form>

          <div className="login-register-prompt">
            <span>Already have an account?</span>
            <a href="/login">Sign in</a>
          </div>
        </section>
      </main>
    </div>
  );
}
