import "./App.css";
import Navbar1 from "./components/Navbar1";
import { BrowserRouter, Routes, Route, Navigate } from "react-router-dom";
import Home from "./pages/Home";

const App = () => {
  return (
    <div>
      <BrowserRouter>
        <Suspense fallback={<div>Loading...</div>}>
          <ScrollToTop />
          <Navbar1 />
          <Routes>
            <Route path="/" element={<Home />} />
            {/* Redirect all unknown routes to Home */}
            <Route path="*" element={<Navigate to="/" replace />} />
          </Routes>
        </Suspense>
      </BrowserRouter>
    </div>
  );
};

export default App;
