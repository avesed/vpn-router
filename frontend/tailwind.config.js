/** @type {import('tailwindcss').Config} */
export default {
  content: ["./index.html", "./src/**/*.{ts,tsx}"],
  theme: {
    extend: {
      colors: {
        brand: {
          DEFAULT: "#1f7ae0",
          dark: "#1458a6"
        }
      }
    }
  },
  plugins: []
};
