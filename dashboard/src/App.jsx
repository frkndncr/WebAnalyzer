import React, { useState } from 'react';
import Sidebar from './components/Sidebar';
import ScanForm from './components/ScanForm';
import ResultsPanel from './components/ResultsPanel';
import AdvancedScannerPanel from './components/AdvancedScannerPanel';
import DashboardOverview from './components/DashboardOverview';
import ThreatIntelPage from './components/ThreatIntelPage';
import NetworkMapPage from './components/NetworkMapPage';
import SettingsPage from './components/SettingsPage';

function App() {
  const [activeTab, setActiveTab] = useState('overview');
  const [currentDomain, setCurrentDomain] = useState('example.com');

  const renderPage = () => {
    switch (activeTab) {
      case 'overview':
        return <DashboardOverview setActiveTab={setActiveTab} setCurrentDomain={setCurrentDomain} />;
      case 'new_scan':
        return <ScanForm setCurrentDomain={setCurrentDomain} setActiveTab={setActiveTab} />;
      case 'results':
        return <ResultsPanel domain={currentDomain} />;
      case 'advanced_scanner':
        return <AdvancedScannerPanel domain={currentDomain} />;
      case 'threat_intel':
        return <ThreatIntelPage />;
      case 'network_map':
        return <NetworkMapPage />;
      case 'settings':
        return <SettingsPage />;
      default:
        return <DashboardOverview setActiveTab={setActiveTab} setCurrentDomain={setCurrentDomain} />;
    }
  };

  return (
    <div className="app-container">
      <div className="cyber-scanline"></div>
      <Sidebar activeTab={activeTab} setActiveTab={setActiveTab} />
      <div className="main-content">
        <div key={activeTab} className="animate-fade-in">
          {renderPage()}
        </div>
      </div>
    </div>
  );
}

export default App;
