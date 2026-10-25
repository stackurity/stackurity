// Vite empties dist/ on build; restore the placeholder that keeps the
// directory in git so `go build` works before the dashboard is built.
import { writeFileSync } from "node:fs";
writeFileSync(new URL("../dist/.gitkeep", import.meta.url), "");
