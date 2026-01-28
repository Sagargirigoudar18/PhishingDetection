import { BrowserRouter as Router, Routes, Route } from 'react-router-dom';
import { useState } from 'react';
import { Home } from './pages/Home';
import { AnalysisResult } from './pages/AnalysisResult';
import { Navbar } from './components/Navbar';
import { Footer } from './components/Footer';
import { About } from './pages/About';
import { Contact } from './pages/Contact';

function App() {
  const [analysisResult, setAnalysisResult] = useState(null);
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState(null);

  const analyzeContent = async (content, contentType) => {
    setIsLoading(true);
    setError(null);
    
    try {
      const response = await fetch('http://localhost:8000/analyze', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          content,
          content_type: contentType,
        }),
      });

      if (!response.ok) {
        throw new Error('Analysis failed. Please try again.');
      }

      const result = await response.json();
      setAnalysisResult(result);
      return result;
    } catch (err) {
      setError(err.message || 'An error occurred during analysis');
      console.error('Analysis error:', err);
      return null;
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <Router>
      <div className="min-h-screen flex flex-col bg-gray-50">
        <Navbar />
        
        <main className="flex-grow container mx-auto px-4 py-8">
          <Routes>
            <Route 
              path="/" 
              element={
                <Home 
                  analyzeContent={analyzeContent} 
                  isLoading={isLoading} 
                  error={error} 
                />
              } 
            />
            <Route 
              path="/result" 
              element={
                <AnalysisResult 
                  result={analysisResult} 
                  error={error} 
                  isLoading={isLoading} 
                />
              } 
            />
            <Route path="/about" element={<About />} />
            <Route path="/contact" element={<Contact />} />
          </Routes>
        </main>
        
        <Footer />
      </div>
    </Router>
  );
}

export default App;
