/** @type {import('tailwindcss').Config} */
export default {
  content: ["./index.html", "./src/**/*.{ts,tsx}"],
  theme: {
    extend: {
      colors: {
        background: "#081018",
        panel: "#111923",
        "panel-soft": "#17212d",
        "panel-strong": "#202c38",
        line: "#314354",
        cyan: "#00dce5",
        blue: "#3b82f6",
        green: "#10b981",
        orange: "#f97316",
        purple: "#a855f7",
        danger: "#ff6b6b",
        text: "#e4edf4",
        muted: "#9fb3c1",
      },
      fontFamily: {
        sans: ["Inter", "system-ui", "sans-serif"],
        mono: ["JetBrains Mono", "ui-monospace", "monospace"],
      },
      boxShadow: {
        glow: "0 0 24px rgba(0, 220, 229, 0.18)",
        "glow-purple": "0 0 24px rgba(168, 85, 247, 0.16)",
      },
    },
  },
  plugins: [],
};
