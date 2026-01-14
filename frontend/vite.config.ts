import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    host: true
  },
  build: {
    // Generate source maps for debugging (optional, can disable in production)
    sourcemap: false,
    // Optimize chunk size warnings threshold
    chunkSizeWarningLimit: 500,
    rollupOptions: {
      output: {
        // Manual chunk splitting for better caching and smaller initial load
        manualChunks: {
          // Core React vendor chunk - cached across all pages
          "vendor-react": ["react", "react-dom", "react-router-dom"],
          // Heavy charting library - only loaded on Dashboard
          "vendor-charts": ["recharts"],
          // Heavy graph library - only loaded on Topology page
          "vendor-xyflow": ["@xyflow/react"],
          // i18n bundle - relatively small but used everywhere
          "vendor-i18n": ["i18next", "react-i18next"]
        }
      }
    },
    // Minification settings
    minify: "esbuild",
    target: "es2020"
  }
});
