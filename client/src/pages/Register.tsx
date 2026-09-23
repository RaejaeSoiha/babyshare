// Registration form page.
import { apiUrl } from "../lib/api";
export default function Register() {
  return (
    <div className="page auth">
      <div className="auth-card">
        <h1>Create Account</h1>
        <p className="muted">Secure access to your shared files.</p>
        <form method="POST" action={apiUrl("/register")} className="form">
          <label>
            Username
            <input name="username" minLength={3} maxLength={32} pattern="[A-Za-z0-9][A-Za-z0-9_-]{2,31}" placeholder="Choose a username" required />
          </label>
          <label>
            Password
            <input type="password" name="password" minLength={12} maxLength={128} placeholder="Create a 12+ character password" required />
          </label>
          <button type="submit" className="btn btn-register">Register</button>
        </form>
        <div className="auth-links">
          <a href="/login">Already have an account?</a>
          <a href="/">Back to home</a>
        </div>
      </div>
    </div>
  );
}
