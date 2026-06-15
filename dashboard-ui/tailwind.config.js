/** @type {import('tailwindcss').Config} */
export default {
  content: ["./index.html", "./src/**/*.{ts,tsx}"],
  theme: {
    extend: {
      colors: {
        background: "#070714",
        sidebar: "#0B0D1E",
        panel: "#12142B",
        "panel-soft": "#171A35",
        "panel-strong": "#171A35",
        line: "#2A2D55",
        cyan: "#00D8FF",
        blue: "#16F4D0",
        green: "#19D6A3",
        orange: "#FF8A3D",
        purple: "#8B5CFF",
        pink: "#FF4FD8",
        danger: "#FF4D6D",
        warning: "#FFB84D",
        text: "#F2F4FF",
        muted: "#9DA7C7",
        soft: "#6F789B",
      },
      fontFamily: {
        sans: ["Inter", "system-ui", "sans-serif"],
        mono: ["JetBrains Mono", "ui-monospace", "monospace"],
      },
      boxShadow: {
        glow: "0 0 24px rgba(0, 216, 255, 0.18)",
        "glow-purple": "0 0 24px rgba(139, 92, 255, 0.18)",
      },
    },
  },
  plugins: [],
};
