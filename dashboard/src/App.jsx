import React, { useState } from 'react';
import Sidebar from './components/Sidebar';
import ScanForm from './components/ScanForm';
import ResultsPanel from './components/ResultsPanel';
import AdvancedScannerPanel from './components/AdvancedScannerPanel';

function App() {
  const [activeTab, setActiveTab] = useState('new_scan');
  const [currentDomain, setCurrentDomain] = useState('example.com');

  return (
    <div className="app-container">
      <Sidebar activeTab={activeTab} setActiveTab={setActiveTab} />
      <div className="main-content">
        <div className="animate-fade-in">
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
