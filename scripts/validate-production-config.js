// CI-only validation for the environment contract. It deliberately avoids starting the app.
process.env.NODE_ENV = "production";
process.env.PUBLIC_BASE_URL = process.env.PUBLIC_BASE_URL || "https://share.example.com";
process.env.SESSION_SECRET = process.env.SESSION_SECRET || "ci-session-secret-with-at-least-thirty-two-characters";
process.env.TRUST_PROXY = process.env.TRUST_PROXY || "true";

const { validateRuntimeConfig } = require("../src/config");

validateRuntimeConfig();
console.info("Production configuration contract is valid.");
