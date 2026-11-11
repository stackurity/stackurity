import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import { BrowserRouter } from "react-router";
import { AuthProvider } from "./auth";
import { App } from "./App";
import { ConfirmHost } from "./components/ConfirmDialog";
import { ReportingBoundary } from "./components/ErrorReports";
import { installErrorReports } from "./clientErrors";
import "./styles.css";
import "./styles/ui-polish.css";

installErrorReports();

createRoot(document.getElementById("root")!).render(
  <StrictMode>
    <ReportingBoundary>
      <BrowserRouter>
        <AuthProvider>
          <App />
          <ConfirmHost />
        </AuthProvider>
      </BrowserRouter>
    </ReportingBoundary>
  </StrictMode>,
);
