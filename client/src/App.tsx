// SPA router: defines page-level routes and shared background.
import { BrowserRouter, Routes, Route, Navigate } from "react-router-dom";
import Background from "./components/Background";
import Home from "./pages/Home";
import Login from "./pages/Login";
import Register from "./pages/Register";
import GuestUpload from "./pages/GuestUpload";
import GuestLogin from "./pages/GuestLogin";
import Dashboard from "./pages/Dashboard";
import Files from "./pages/Files";
import Admin from "./pages/Admin";
import NotFound from "./pages/NotFound";
import "./App.css";

export default function App() {
  return (
    <BrowserRouter>
      <Background />
      <Routes>
        <Route path="/" element={<Home />} />
        <Route path="/login" element={<Login />} />
        <Route path="/register" element={<Register />} />
        <Route path="/guest-upload" element={<GuestUpload />} />
        <Route path="/guest-login" element={<GuestLogin />} />
        <Route path="/dashboard" element={<Dashboard />} />
        <Route path="/files" element={<Files />} />
        <Route path="/admin" element={<Admin />} />
        <Route path="/list" element={<Navigate to="/files" replace />} />
        <Route path="/manage-users" element={<Navigate to="/admin" replace />} />
        <Route path="/home" element={<Navigate to="/" replace />} />
        <Route path="*" element={<NotFound />} />
      </Routes>
    </BrowserRouter>
  );
}
