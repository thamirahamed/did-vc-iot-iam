import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

export default defineConfig({
  plugins: [react()],
  server: {
    host: "0.0.0.0",
    port: 5173,
    strictPort: true,
    proxy: {
      "/api/issuer": {
        target: process.env.ISSUER_PROXY_TARGET || "http://localhost:8000",
        changeOrigin: true,
        rewrite: (path) => path.replace(/^\/api\/issuer/, ""),
      },
      "/api/verifier": {
        target: process.env.VERIFIER_PROXY_TARGET || "http://localhost:8001",
        changeOrigin: true,
        rewrite: (path) => path.replace(/^\/api\/verifier/, ""),
      },
      "/api/fabric-adapter": {
        target: process.env.FABRIC_ADAPTER_PROXY_TARGET || "http://localhost:8010",
        changeOrigin: true,
        rewrite: (path) => path.replace(/^\/api\/fabric-adapter/, ""),
      },
      "/api/dashboard": {
        target: process.env.DASHBOARD_API_PROXY_TARGET || "http://localhost:8020",
        changeOrigin: true,
        rewrite: (path) => path.replace(/^\/api\/dashboard/, ""),
      },
    },
  },
});
