// Fallback route when no match is found.
export default function NotFound() {
  return (
    <div className="page auth">
      <div className="auth-card">
        <h1>Page not found</h1>
        <p className="muted">The page you requested does not exist.</p>
        <div className="auth-links">
          <a href="/">Go home</a>
        </div>
      </div>
    </div>
  );
}
