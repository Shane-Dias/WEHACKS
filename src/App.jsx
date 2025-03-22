import "./App.css";
import Navbar1 from "./components/Navbar1";
import { BrowserRouter, Routes, Route, Navigate } from "react-router-dom";
import Home from "./pages/Home";
import Navbar1 from "./components/Navbar1";
import React, { Suspense, lazy } from "react";
import HeatMap from "./components/Heatmap";

const HeatMap = lazy(() => import("./components/Heatmap"));

if ("serviceWorker" in navigator) {
  navigator.serviceWorker
    .register("./sw.js")
    .then((registration) => {
      console.log("Service Worker registered:", registration);
    })
    .catch((error) => {
      console.error("Service Worker registration failed:", error);
    });
}

const App = () => {
  return (
    <div>
      <BrowserRouter>
        <Suspense fallback={<div>Loading...</div>}>
          <ScrollToTop />
          <Navbar1 />
          <Routes>
            <Route path="/" element={<Home />} />
            <Route path="/heatmap" element={<HeatMap />} />
            {/* Redirect all unknown routes to Home */}
            <Route path="*" element={<Navigate to="/" replace />} />
          </Routes>
        </Suspense>
      </BrowserRouter>
    </div>
  );
};

export default App;
