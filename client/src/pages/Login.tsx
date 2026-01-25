// Login form page.
export default function Login() {
  return (
    <div className="page auth">
      <div className="auth-card">
        <h1>Welcome Back</h1>
        <p className="muted">Sign in to manage your files.</p>
        <form method="POST" action="/login" className="form">
          <label>
            Username
            <input name="username" placeholder="Enter username" required />
          </label>
          <label>
            Password
            <input type="password" name="password" placeholder="Enter password" required />
          </label>
          <button type="submit" className="btn btn-login">Login</button>
        </form>
        <div className="auth-links">
          <a href="/register">Create account</a>
          <a href="/">Back to home</a>
        </div>
      </div>
    </div>
  );
}
