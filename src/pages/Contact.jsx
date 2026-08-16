import React, { useState } from 'react';
import { Mail, MessageSquare, AlertTriangle, CheckCircle2 } from 'lucide-react';

const Contact = () => {
  const [activeTab, setActiveTab] = useState('feedback');
  const [feedbackSuccess, setFeedbackSuccess] = useState(false);
  const [reportSuccess, setReportSuccess] = useState(false);

  // Form states
  const [isSubmitting, setIsSubmitting] = useState(false);

  // Mock submission handler for feedback
  const handleFeedbackSubmit = (e) => {
    e.preventDefault();
    setIsSubmitting(true);
    // Simulate backend integration
    setTimeout(() => {
      setIsSubmitting(false);
      setFeedbackSuccess(true);
    }, 800);
  };

  // Mock submission handler for reporting false positive
  const handleReportSubmit = (e) => {
    e.preventDefault();
    setIsSubmitting(true);
    // Simulate backend integration
    setTimeout(() => {
      setIsSubmitting(false);
      setReportSuccess(true);
    }, 800);
  };

  return (
    <div className="flex flex-col min-h-screen bg-slate-950 text-slate-200 font-sans">
      <div className="max-w-5xl mx-auto px-4 sm:px-6 lg:px-8 py-12 w-full">

        {/* Header */}
        <header className="mb-12 text-center md:text-left">
          <h1 className="text-3xl md:text-5xl font-black text-slate-50 mb-4 tracking-tight">
            Contact Us
          </h1>
          <p className="text-lg text-slate-400 max-w-2xl">
            We typically respond within 1–2 business days. Choose the best way to reach us below.
          </p>
        </header>

        <div className="grid grid-cols-1 lg:grid-cols-3 gap-8">

          {/* Direct Contact Option */}
          <div className="lg:col-span-1 space-y-6">
            <div className="bg-slate-900 border border-slate-800 rounded-2xl p-6">
              <div className="w-12 h-12 bg-indigo-500/10 rounded-xl flex items-center justify-center text-indigo-400 mb-6">
                <Mail className="w-6 h-6" />
              </div>
              <h2 className="text-xl font-bold text-slate-50 mb-2">Direct Email</h2>
              <p className="text-slate-400 text-sm mb-6">
                For general questions, support, partnerships, and business inquiries.
              </p>
              <a
                href="mailto:contact@urlscanonline.com"
                className="inline-flex w-full items-center justify-center px-4 py-2.5 bg-slate-800 hover:bg-slate-700 text-slate-200 font-medium rounded-lg transition-colors border border-slate-700"
              >
                contact@urlscanonline.com
              </a>
            </div>
          </div>

          {/* Forms Section */}
          <div className="lg:col-span-2">
            <div className="bg-slate-900 border border-slate-800 rounded-2xl overflow-hidden">

              {/* Tabs */}
              <div className="flex border-b border-slate-800">
                <button
                  onClick={() => setActiveTab('feedback')}
                  className={`flex-1 py-4 px-6 text-sm font-medium flex items-center justify-center gap-2 transition-colors ${
                    activeTab === 'feedback'
                      ? 'bg-slate-800/50 text-indigo-400 border-b-2 border-indigo-500'
                      : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/30'
                  }`}
                >
                  <MessageSquare className="w-4 h-4" />
                  Feedback
                </button>
                <button
                  onClick={() => setActiveTab('report')}
                  className={`flex-1 py-4 px-6 text-sm font-medium flex items-center justify-center gap-2 transition-colors ${
                    activeTab === 'report'
                      ? 'bg-slate-800/50 text-indigo-400 border-b-2 border-indigo-500'
                      : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/30'
                  }`}
                >
                  <AlertTriangle className="w-4 h-4" />
                  Report False Positive
                </button>
              </div>

              <div className="p-6 md:p-8">
                {/* Feedback Form */}
                {activeTab === 'feedback' && (
                  feedbackSuccess ? (
                    <div className="text-center py-12">
                      <div className="w-16 h-16 bg-emerald-500/10 rounded-full flex items-center justify-center text-emerald-500 mx-auto mb-4">
                        <CheckCircle2 className="w-8 h-8" />
                      </div>
                      <h3 className="text-xl font-bold text-slate-50 mb-2">Feedback Submitted</h3>
                      <p className="text-slate-400 mb-6 max-w-sm mx-auto">
                        Thank you for your feedback! We appreciate your help in improving URLScannerOnline.
                      </p>
                      <button
                        onClick={() => setFeedbackSuccess(false)}
                        className="text-indigo-400 hover:text-indigo-300 font-medium text-sm"
                      >
                        Submit another response
                      </button>
                    </div>
                  ) : (
                    <form onSubmit={handleFeedbackSubmit} className="space-y-6">
                      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                        <div className="space-y-2">
                          <label htmlFor="name" className="text-sm font-medium text-slate-300">Name <span className="text-slate-600">(optional)</span></label>
                          <input
                            id="name"
                            type="text"
                            placeholder="Jane Doe"
                            className="w-full bg-slate-950 border border-slate-800 rounded-lg px-4 py-2.5 text-slate-200 focus:outline-none focus:border-indigo-500 focus:ring-1 focus:ring-indigo-500 transition-colors"
                          />
                        </div>
                        <div className="space-y-2">
                          <label htmlFor="email" className="text-sm font-medium text-slate-300">Email <span className="text-slate-600">(optional)</span></label>
                          <input
                            id="email"
                            type="email"
                            placeholder="jane@example.com"
                            className="w-full bg-slate-950 border border-slate-800 rounded-lg px-4 py-2.5 text-slate-200 focus:outline-none focus:border-indigo-500 focus:ring-1 focus:ring-indigo-500 transition-colors"
                          />
                        </div>
                      </div>

                      <div className="space-y-2">
                        <label htmlFor="type" className="text-sm font-medium text-slate-300">Feedback Type *</label>
                        <select
                          id="type"
                          required
                          className="w-full bg-slate-950 border border-slate-800 rounded-lg px-4 py-2.5 text-slate-200 focus:outline-none focus:border-indigo-500 focus:ring-1 focus:ring-indigo-500 transition-colors appearance-none"
                        >
                          <option value="">Select a category...</option>
                          <option value="suggestion">Feature Suggestion</option>
                          <option value="bug">Bug Report</option>
                          <option value="ui">UI/UX Issue</option>
                          <option value="other">Other</option>
                        </select>
                      </div>

                      <div className="space-y-2">
                        <label htmlFor="message" className="text-sm font-medium text-slate-300">Message *</label>
                        <textarea
                          id="message"
                          required
                          rows="4"
                          placeholder="How can we improve?"
                          className="w-full bg-slate-950 border border-slate-800 rounded-lg px-4 py-2.5 text-slate-200 focus:outline-none focus:border-indigo-500 focus:ring-1 focus:ring-indigo-500 transition-colors resize-none"
                        ></textarea>
                      </div>

                      <button
                        type="submit"
                        disabled={isSubmitting}
                        className="w-full flex items-center justify-center px-6 py-3 bg-indigo-600 hover:bg-indigo-500 disabled:opacity-50 disabled:cursor-not-allowed text-white font-medium rounded-lg transition-colors shadow-lg shadow-indigo-600/20"
                      >
                        {isSubmitting ? 'Submitting...' : 'Submit Feedback'}
                      </button>
                    </form>
                  )
                )}

                {/* Report False Positive Form */}
                {activeTab === 'report' && (
                  reportSuccess ? (
                    <div className="text-center py-12">
                      <div className="w-16 h-16 bg-emerald-500/10 rounded-full flex items-center justify-center text-emerald-500 mx-auto mb-4">
                        <CheckCircle2 className="w-8 h-8" />
                      </div>
                      <h3 className="text-xl font-bold text-slate-50 mb-2">Report Submitted</h3>
                      <p className="text-slate-400 mb-6 max-w-sm mx-auto">
                        Thank you for reporting this false positive. Our team will review the finding to improve scan accuracy.
                      </p>
                      <button
                        onClick={() => setReportSuccess(false)}
                        className="text-indigo-400 hover:text-indigo-300 font-medium text-sm"
                      >
                        Submit another report
                      </button>
                    </div>
                  ) : (
                    <form onSubmit={handleReportSubmit} className="space-y-6">
                      <div className="space-y-2">
                        <label htmlFor="url" className="text-sm font-medium text-slate-300">Website URL *</label>
                        <input
                          id="url"
                          type="url"
                          required
                          placeholder="https://example.com"
                          className="w-full bg-slate-950 border border-slate-800 rounded-lg px-4 py-2.5 text-slate-200 focus:outline-none focus:border-indigo-500 focus:ring-1 focus:ring-indigo-500 transition-colors"
                        />
                      </div>

                      <div className="space-y-2">
                        <label htmlFor="finding" className="text-sm font-medium text-slate-300">Finding Name or ID *</label>
                        <input
                          id="finding"
                          type="text"
                          required
                          placeholder="e.g. Missing Content-Security-Policy"
                          className="w-full bg-slate-950 border border-slate-800 rounded-lg px-4 py-2.5 text-slate-200 focus:outline-none focus:border-indigo-500 focus:ring-1 focus:ring-indigo-500 transition-colors"
                        />
                      </div>

                      <div className="space-y-2">
                        <label htmlFor="reason" className="text-sm font-medium text-slate-300">Reason it's a false positive *</label>
                        <textarea
                          id="reason"
                          required
                          rows="2"
                          placeholder="Why is this finding incorrect for your environment?"
                          className="w-full bg-slate-950 border border-slate-800 rounded-lg px-4 py-2.5 text-slate-200 focus:outline-none focus:border-indigo-500 focus:ring-1 focus:ring-indigo-500 transition-colors resize-none"
                        ></textarea>
                      </div>

                      <div className="space-y-2">
                        <label htmlFor="details" className="text-sm font-medium text-slate-300">Additional details <span className="text-slate-600">(optional)</span></label>
                        <textarea
                          id="details"
                          rows="2"
                          placeholder="Any other context that would help us review this report"
                          className="w-full bg-slate-950 border border-slate-800 rounded-lg px-4 py-2.5 text-slate-200 focus:outline-none focus:border-indigo-500 focus:ring-1 focus:ring-indigo-500 transition-colors resize-none"
                        ></textarea>
                      </div>

                      <div className="space-y-2">
                        <label htmlFor="reportEmail" className="text-sm font-medium text-slate-300">Contact Email <span className="text-slate-600">(optional)</span></label>
                        <input
                          id="reportEmail"
                          type="email"
                          placeholder="We'll only use this to follow up on your report if needed"
                          className="w-full bg-slate-950 border border-slate-800 rounded-lg px-4 py-2.5 text-slate-200 focus:outline-none focus:border-indigo-500 focus:ring-1 focus:ring-indigo-500 transition-colors"
                        />
                      </div>

                      <button
                        type="submit"
                        disabled={isSubmitting}
                        className="w-full flex items-center justify-center px-6 py-3 bg-indigo-600 hover:bg-indigo-500 disabled:opacity-50 disabled:cursor-not-allowed text-white font-medium rounded-lg transition-colors shadow-lg shadow-indigo-600/20"
                      >
                        {isSubmitting ? 'Submitting...' : 'Submit Report'}
                      </button>
                    </form>
                  )
                )}
              </div>
            </div>
          </div>
        </div>

      </div>
    </div>
  );
};

export default Contact;
