import React from "react";
import ReactDOM from "react-dom/client";
import { RouterProvider, createBrowserRouter, Navigate } from "react-router-dom";
import App from "./App";
import Dashboard from "./pages/Dashboard";
import Endpoints from "./pages/Endpoints";
import PiaLogin from "./pages/PiaLogin";
import EgressManager from "./pages/EgressManager";
import RouteRules from "./pages/RouteRules";
import DomainCatalog from "./pages/DomainCatalog";
import IpCatalog from "./pages/IpCatalog";
import IngressManager from "./pages/IngressManager";
import BackupRestore from "./pages/BackupRestore";
import "./index.css";
import "./i18n";

const router = createBrowserRouter([
  {
    path: "/",
    element: <App />,
    children: [
      { index: true, element: <Dashboard /> },
      { path: "ingress", element: <IngressManager /> },
      { path: "egress", element: <EgressManager /> },
      { path: "profiles", element: <Navigate to="/egress" replace /> },
      { path: "rules", element: <RouteRules /> },
      { path: "domain-catalog", element: <DomainCatalog /> },
      { path: "ip-catalog", element: <IpCatalog /> },
      { path: "endpoints", element: <Endpoints /> },
      { path: "pia", element: <PiaLogin /> },
      { path: "backup", element: <BackupRestore /> }
    ]
  }
]);

ReactDOM.createRoot(document.getElementById("root")!).render(
  <React.StrictMode>
    <RouterProvider router={router} />
  </React.StrictMode>
);
