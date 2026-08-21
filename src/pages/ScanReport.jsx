import React, { useState, useEffect, useRef } from 'react';
import { useParams, Navigate, useNavigate } from 'react-router-dom';
import { useAuth } from '../contexts/AuthContext';
import { supabase } from '../lib/supabase';
import SimpleReport from '../components/scanner/SimpleReport';
import TechnicalReport from '../components/scanner/TechnicalReport';
import ReportHeader from '../components/scanner/ReportHeader';
import { generateReportPdf } from '../lib/pdfGenerator';
import { AlertCircle } from 'lucide-react';

const ScanReport = () => {
  const { scanId } = useParams();
  const { user } = useAuth();
  const navigate = useNavigate();

  const [scan, setScan] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [activeMode, setActiveMode] = useState('simple');

  const reportRef = useRef(null);

  useEffect(() => {
    if (!user) {
      setLoading(false);
      return;
    }

    const fetchScan = async () => {
      try {
        const { data, error: err } = await supabase
          .from('scans')
          .select('*')
          .eq('id', scanId)
          .single();

        if (err) throw err;
        setScan(data);
      } catch (err) {
        console.error('Error fetching scan:', err);
        setError('Report not found or access denied.');
      } finally {
        setLoading(false);
      }
    };

    fetchScan();
  }, [scanId, user]);

  if (!user) {
    return <Navigate to="/login" replace />;
  }

  if (loading) {
    return (
      <div className="flex justify-center items-center h-[60vh]">
        <div className="text-slate-400">Loading report...</div>
      </div>
    );
  }

  if (error || !scan) {
    return (
      <div className="max-w-4xl mx-auto p-8">
        <div className="bg-rose-500/10 border border-rose-500/30 rounded-xl p-8 text-center text-rose-400">
          <AlertCircle className="w-12 h-12 mx-auto mb-4 opacity-80" />
          <h2 className="text-xl font-bold mb-2">Report Not Found</h2>
          <p className="mb-6">{error || 'The requested report could not be found or you do not have permission to view it.'}</p>
          <button
            type="button"
            onClick={() => navigate('/history')}
            className="px-6 py-2 bg-slate-800 hover:bg-slate-700 text-slate-200 rounded-lg transition-colors border border-slate-700"
          >
            Return to History
          </button>
        </div>
      </div>
    );
  }

  const handleExportPdf = async () => {
    try {
      await generateReportPdf(reportRef.current, scan.target_url);
    } catch (err) {
      console.error('Failed to generate PDF:', err);
      alert('Failed to generate PDF report.');
    }
  };

  return (
    <div className="max-w-6xl mx-auto p-4 sm:p-6 lg:p-8">
      <ReportHeader
        url={scan.target_url}
        score={scan.score}
        timestamp={scan.created_at}
        activeMode={activeMode}
        onToggleMode={setActiveMode}
        onExportPdf={handleExportPdf}
        reportData={scan.report_data}
      />
      
      <div ref={reportRef} className="bg-slate-950 p-6 sm:p-8 rounded-2xl border border-slate-800 shadow-2xl relative overflow-hidden">
        <div className="absolute top-0 right-0 p-8 opacity-5 pointer-events-none">
          <div className="text-[120px] font-black tracking-tighter leading-none select-none">
            {scan.score}
          </div>
        </div>

        {activeMode === 'simple' ? (
          <SimpleReport
            url={scan.target_url}
            score={scan.score}
            reportData={scan.report_data}
          />
        ) : (
          <TechnicalReport
            url={scan.target_url}
            score={scan.score}
            reportData={scan.report_data}
          />
        )}
      </div>
    </div>
  );
};

export default ScanReport;
