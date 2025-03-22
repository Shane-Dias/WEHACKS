import React, { Suspense, lazy } from "react";
import "./App.css";
import Navbar1 from "./components/Navbar1";
import { BrowserRouter, Routes, Route, Navigate } from "react-router-dom";
import Home from "./pages/Home";
import VoiceToText from "./components/VoiceToText";
import SignUp from "./pages/SignUp";
import Login from "./pages/Login";
import ScrollToTop from "./lib/ScrollToTop";
import { AuthProvider, useAuth } from "./context/AuthContext";
import UserProfile from "./pages/UserProfile";
import { LocationProvider } from "../src/context/LocationContext";
import HeatMap from "./components/Heatmap";

const UserDashboard = lazy(() => import("./pages/UserDashboard"));
const AdminDashboard = lazy(() => import("./pages/AdminDashboard"));
const HeatMap = lazy(() => import("./components/Heatmap"));
const IncidentReportForm = lazy(() => import("./pages/IncidentReportForm2"));
const Chatbot = lazy(() => import("./pages/chatbotTrial"));

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
    <AuthProvider>
      <LocationProvider>
        <div>
          <BrowserRouter>
            <Suspense fallback={<div>Loading...</div>}>
              <ScrollToTop />
              <Navbar1 />
              <Routes>
                <Route path="/" element={<Home />} />
                <Route
                  path="/report-incident"
                  element={<IncidentReportForm />}
                />
                {/* Protect Admin Route */}
                <Route path="/admin" element={<AdminDashboard />} />
                {/* Protect User Route */}
                <Route path="/my-reports" element={<UserDashboard />} />
                <Route path="/my-reports" element={<UserDashboard />} />
                <Route path="/admin" element={<AdminDashboard />} />
                <Route path="/About" element={<AboutUs />} />
                <Route path="/heatmap" element={<HeatMap />} />
                <Route path="/voice-report" element={<VoiceToText />} />
                <Route path="/signUp" element={<SignUp />} />
                <Route path="/login" element={<Login />} />
                <Route path="chatbot" element={<Chatbot />} />
                {/* Redirect all unknown routes to Home */}
                <Route path="*" element={<Navigate to="/" replace />} />
              </Routes>
            </Suspense>
          </BrowserRouter>
        </div>
      </LocationProvider>
    </AuthProvider>
  );
};

export default App;
