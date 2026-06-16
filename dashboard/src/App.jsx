import React, { useState } from 'react';
import Sidebar from './components/Sidebar';
import ScanForm from './components/ScanForm';
import ResultsPanel from './components/ResultsPanel';
import AdvancedScannerPanel from './components/AdvancedScannerPanel';
import DashboardOverview from './components/DashboardOverview';

function App() {
  const [activeTab, setActiveTab] = useState('overview');
  const [currentDomain, setCurrentDomain] = useState('example.com');

  return (
    <div className="app-container">
      <div className="cyber-scanline"></div>
      <Sidebar activeTab={activeTab} setActiveTab={setActiveTab} />
      <div className="main-content">
        <div className="animate-fade-in">
          {activeTab === 'overview' &&
            <DashboardOverview 
              setActiveTab={setActiveTab}
              setCurrentDomain={setCurrentDomain}
            />
          }
          {activeTab === 'new_scan' && 
            <ScanForm 
              setCurrentDomain={setCurrentDomain} 
              setActiveTab={setActiveTab} 
            />
          }
          {activeTab === 'results' && 
            <ResultsPanel domain={currentDomain} />
          }
          {activeTab === 'advanced_scanner' && 
            <AdvancedScannerPanel domain={currentDomain} />
          }
        </div>
      </div>
    </div>
  );
}

export default App;
