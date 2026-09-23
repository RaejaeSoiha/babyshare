// Vite configuration. The proxy exists only for the local development server.
import { defineConfig } from "vite";
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

export default defineConfig({
  plugins: [react()],
  server: {
    port: 3000,
    proxy: Object.fromEntries(backendRoutes.map((route) => [route, backend])),
  },
});
