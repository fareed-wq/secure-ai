import { useState } from 'react';
import { generateStructuredPdf } from '../lib/pdfGenerator';

const usePdfGenerator = () => {
  const [isGeneratingPdf, setIsGeneratingPdf] = useState(false);

  const generatePdf = async (scanData, scanMode, reportMode) => {
    setIsGeneratingPdf(true);
    try {
      // Small timeout to show the loading state before synchronous PDF generation blocks the thread
      await new Promise(resolve => setTimeout(resolve, 100));
      generateStructuredPdf(scanData, scanMode, reportMode);
    } catch (error) {
      console.error('Failed to generate PDF', error);
      alert("There was an error generating the PDF. Please try again.");
    } finally {
      setIsGeneratingPdf(false);
    }
  };

  return { isGeneratingPdf, generatePdf };
};

export default usePdfGenerator;
