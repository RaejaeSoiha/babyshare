// Vite configuration. The proxy exists only for the local development server.
import { defineConfig } from "vite";
import type { IncomingMessage } from "node:http";
import react from "@vitejs/plugin-react";

const backend = process.env.BABYSHARE_API_PROXY || "http://127.0.0.1:3100";
const backendRoutes = [
  "/api",
  "/download",
  "/guest-download",
  "/guest-login",
  "/guest-upload",
  "/login",
  "/logout",
  "/register",
  "/secure-download",
  "/upload",
];
const spaRoutes = new Set(["/guest-login", "/guest-upload", "/login", "/register"]);

const proxy = Object.fromEntries(backendRoutes.map((route) => [
  route,
  spaRoutes.has(route)
    ? {
      target: backend,
      // Browser navigation must reach Vite's SPA fallback; form submissions still go to Express.
      bypass: (request: IncomingMessage) => request.method === "GET" ? request.url : undefined,
    }
    : backend,
]));

export default defineConfig({
  plugins: [react()],
  server: {
    port: 3000,
    proxy,
  },
});
