import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import { BrowserRouter } from "react-router";
import { AuthProvider } from "./auth";
import { App } from "./App";
import { ConfirmHost } from "./components/ConfirmDialog";
import "./styles.css";

createRoot(document.getElementById("root")!).render(
  <StrictMode>
    <BrowserRouter>
      <AuthProvider>
        <App />
        <ConfirmHost />
      </AuthProvider>
    </BrowserRouter>
  </StrictMode>,
);
