import React from 'react';
import { BrowserRouter as Router, Routes, Route, Navigate } from 'react-router-dom';
import { Landing } from './pages/Landing';
import { ScanStatus } from './pages/ScanStatus';
import { Dashboard } from './pages/Dashboard';
import { Findings } from './pages/Findings';
import { Architecture } from './pages/Architecture';
import { Diagnosis } from './pages/Diagnosis';
import { Fixes } from './pages/Fixes';

export const App: React.FC = () => {
  return (
    <Router>
      <Routes>
        <Route path="/" element={<Landing />} />
        <Route path="/scans/:id" element={<ScanStatus />} />
        <Route path="/scans/:id/dashboard" element={<Dashboard />} />
        <Route path="/scans/:id/findings" element={<Findings />} />
        <Route path="/scans/:id/architecture" element={<Architecture />} />
        <Route path="/scans/:id/diagnosis" element={<Diagnosis />} />
        <Route path="/scans/:id/fixes" element={<Fixes />} />
        {/* Fallback */}
        <Route path="*" element={<Navigate to="/" replace />} />
      </Routes>
    </Router>
  );
};

export default App;
