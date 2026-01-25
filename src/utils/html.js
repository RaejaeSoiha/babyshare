// Render a simple HTML error page for non-SPA flows.
function renderError(title, message, actionsHtml = "") {
  return `
    <!DOCTYPE html>
    <html lang="en">
    <head>
      <meta charset="UTF-8">
      <title> Error</title>
      <style>
        body {
          margin:0;
          padding:0;
          font-family:"Segoe UI", sans-serif;
          background:#000;
          overflow:hidden;
        }
        .container.card {
          background:#fff;
          padding:2rem 3rem;
          border-radius:15px;
          box-shadow:0 8px 20px rgba(0,0,0,0.4);
          text-align:center;
          max-width:450px;
          margin:10% auto;
          position:relative;
          z-index:1;
        }
      </style>
    </head>
    <body>
      <div class="container card">
        <h2 style="color:#d93025;"> ${title}</h2>
        <p>${message}</p>
        <p>${actionsHtml}</p>
      </div>
    </body>
    </html>
  `;
}

// Render a simple HTML success page for non-SPA flows.
function renderSuccess(title, message, actionsHtml = "") {
  return `
    <!DOCTYPE html>
    <html lang="en">
    <head>
      <meta charset="UTF-8">
      <title> Success</title>
      <style>
        body {
          margin:0;
          padding:0;
          font-family:"Segoe UI", sans-serif;
          background:#000;
          overflow:hidden;
        }
        .container.card {
          background:#fff;
          padding:2rem 3rem;
          border-radius:15px;
          box-shadow:0 8px 20px rgba(0,0,0,0.4);
          text-align:center;
          max-width:450px;
          margin:10% auto;
          position:relative;
          z-index:1;
        }
      </style>
    </head>
    <body>
      <div class="container card">
        <h2 style="color:green;">${title}</h2>
        <p>${message}</p>
        <p>${actionsHtml}</p>
      </div>
    </body>
    </html>
  `;
}

// Render an access chooser for protected downloads.
function renderAccessOptions(title, message, previewUrl, downloadUrl) {
  return `
    <!DOCTYPE html>
    <html lang="en">
    <head>
      <meta charset="UTF-8">
      <title>${title}</title>
      <style>
        body {
          margin:0;
          padding:0;
          font-family:"Segoe UI", sans-serif;
          background:#000;
          overflow:hidden;
        }
        .container.card {
          background:#fff;
          padding:2rem 3rem;
          border-radius:15px;
          box-shadow:0 8px 20px rgba(0,0,0,0.4);
          text-align:center;
          max-width:450px;
          margin:10% auto;
          position:relative;
          z-index:1;
        }
        .actions { display:flex; gap:12px; justify-content:center; margin-top:1rem; }
        .actions a { text-decoration:none; }
      </style>
    </head>
    <body>
      <div class="container card">
        <h2>${title}</h2>
        <p>${message}</p>
        <div class="actions">
          <a href="${previewUrl}">Review</a>
          <a href="${downloadUrl}">Download</a>
        </div>
      </div>
    </body>
    </html>
  `;
}

module.exports = { renderError, renderSuccess, renderAccessOptions };
