// Small HTML renderers retained for public password-gated sharing flows.
function escapeHtml(value) {
  return String(value ?? "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

function renderDocument(title, body) {
  return `<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <meta name="referrer" content="same-origin">
    <title>${escapeHtml(title)} | BabyShare</title>
    <style>
      body { align-items:center; background:#0b0f16; color:#eef2f7; display:flex; font:16px system-ui,sans-serif; justify-content:center; margin:0; min-height:100vh; padding:24px; }
      main { background:#141a24; border:1px solid #334155; border-radius:8px; box-shadow:0 18px 40px rgba(0,0,0,.35); max-width:420px; padding:28px; width:100%; }
      h1 { font-size:1.5rem; margin:0 0 8px; } p { color:#c8d3ea; line-height:1.5; } input { box-sizing:border-box; margin:12px 0; padding:12px; width:100%; }
      .actions { display:flex; flex-wrap:wrap; gap:10px; } button,a { background:#1faa6f; border:0; border-radius:6px; color:white; cursor:pointer; font:inherit; padding:10px 14px; text-decoration:none; } .alt { background:#1f9cf3; }
    </style>
  </head>
  <body><main>${body}</main></body>
</html>`;
}

function renderError(title, message) {
  return renderDocument(title, `<h1>${escapeHtml(title)}</h1><p>${escapeHtml(message)}</p><a href="/">Return home</a>`);
}

function renderPasswordPrompt({ title, filename, actionUrl, hiddenFields = {}, error = "" }) {
  const fields = Object.entries(hiddenFields)
    .map(([name, value]) => `<input type="hidden" name="${escapeHtml(name)}" value="${escapeHtml(value)}">`)
    .join("");
  const errorMessage = error ? `<p role="alert">${escapeHtml(error)}</p>` : "";
  return renderDocument(
    title,
    `<h1>${escapeHtml(title)}</h1>
      <p>${escapeHtml(filename)}</p>
      ${errorMessage}
      <form method="post" action="${escapeHtml(actionUrl)}">
        ${fields}
        <label>Password <input type="password" name="password" autocomplete="current-password" required maxlength="128"></label>
        <div class="actions">
          <button type="submit" name="action" value="preview">Preview in browser</button>
          <button class="alt" type="submit" name="action" value="download">Download file</button>
        </div>
      </form>`
  );
}

function renderGuestAccess({ filename, previewUrl, downloadUrl }) {
  return renderDocument(
    "Guest access",
    `<h1>Guest access</h1>
      <p>${escapeHtml(filename)}</p>
      <div class="actions">
        <a href="${escapeHtml(previewUrl)}">Preview in browser</a>
        <a class="alt" href="${escapeHtml(downloadUrl)}">Download file</a>
      </div>`
  );
}

module.exports = { escapeHtml, renderError, renderGuestAccess, renderPasswordPrompt };
