// Registration form page.
export default function Register() {
  return (
    <div className="page auth">
      <div className="auth-card">
        <h1>Create Account</h1>
        <p className="muted">Secure access to your shared files.</p>
        <form method="POST" action="/register" className="form">
          <label>
            Username
            <input name="username" placeholder="Choose a username" required />
          </label>
          <label>
            Password
            <input type="password" name="password" placeholder="Create a password" required />
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
