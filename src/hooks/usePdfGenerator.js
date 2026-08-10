import { useState } from 'react';

const usePdfGenerator = () => {
  const [isGeneratingPdf, setIsGeneratingPdf] = useState(false);

  const generatePdf = async () => {
    setIsGeneratingPdf(true);
    try {
      // Allow React state to update if needed, then trigger print
      await new Promise(resolve => setTimeout(resolve, 100));
      window.print();
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
