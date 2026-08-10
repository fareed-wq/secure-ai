import { useState } from 'react';

const usePdfGenerator = () => {
  const [isGeneratingPdf, setIsGeneratingPdf] = useState(false);

  const generatePdf = async (element, url) => {
    if (!element) return;
    setIsGeneratingPdf(true);
    
    try {
      const html2canvas = (await import('html2canvas')).default;
      const { jsPDF } = await import('jspdf');
      
      // Temporarily hide elements not meant for print
      const hideElements = element.querySelectorAll('.print\\:hidden');
      hideElements.forEach(el => el.style.display = 'none');
      
      let canvas;
      try {
        canvas = await html2canvas(element, {
          scale: 2,
          useCORS: true,
          logging: false,
          backgroundColor: '#020617', // slate-950
          windowWidth: element.scrollWidth,
          windowHeight: element.scrollHeight
        });
      } finally {
        hideElements.forEach(el => el.style.display = '');
      }

      const imgData = canvas.toDataURL('image/png');
      const pdf = new jsPDF('p', 'mm', 'a4');
      
      const pdfWidth = pdf.internal.pageSize.getWidth();
      const pdfHeight = pdf.internal.pageSize.getHeight();
      const imgWidth = canvas.width;
      const imgHeight = canvas.height;
      const ratio = pdfWidth / imgWidth;
      const totalPdfHeight = imgHeight * ratio;

      let heightLeft = totalPdfHeight;
      let position = 0;

      pdf.addImage(imgData, 'PNG', 0, position, pdfWidth, totalPdfHeight);
      heightLeft -= pdfHeight;

      while (heightLeft > 0) {
        position = heightLeft - totalPdfHeight;
        pdf.addPage();
        pdf.addImage(imgData, 'PNG', 0, position, pdfWidth, totalPdfHeight);
        heightLeft -= pdfHeight;
      }
      
      pdf.save(`SecureAI-Report-${url.replace(/^https?:\/\//, '').split('/')[0]}.pdf`);
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
