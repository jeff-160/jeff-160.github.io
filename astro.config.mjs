// @ts-check
import { defineConfig } from "astro/config";
import tailwindcss from "@tailwindcss/vite";

// https://astro.build/config
export default defineConfig({
  site: "https://jeff-160.github.io",
  base: "/",
  trailingSlash: "always",
  output: "static",
  vite: {
    plugins: [tailwindcss()],
  },
});
