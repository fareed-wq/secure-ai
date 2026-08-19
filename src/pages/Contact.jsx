import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { CheckCircle2, ArrowLeft, ChevronDown, AlertTriangle } from 'lucide-react';

import { useSEO } from '../hooks/useSEO';

const Contact = () => {
  useSEO({
    title: 'Contact Us',
    description: 'Get in touch with URLScannerOnline for support, sales, or general questions.',
    path: '/contact'
  });
  const navigate = useNavigate();
  const [submitSuccess, setSubmitSuccess] = useState(false);
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [submitError, setSubmitError] = useState('');

  // Topic state maps to backend expectations while allowing fresh UI labels
  const [topic, setTopic] = useState('General Question');

  const handleBack = () => {
    if (window.history.state && window.history.state.idx > 0) {
      navigate(-1);
    } else {
      navigate('/', { replace: true });
    }
  };

  const handleTopicChange = (e) => {
    setTopic(e.target.value);
    setSubmitError('');
  };

  const isUrlRequired = topic === 'Security / Bug Report';

  const handleSubmit = async (e) => {
    e.preventDefault();
    setSubmitError('');

    let normalizedUrl = '';
    const formUrl = e.target.elements.url?.value?.trim() || '';

    if (formUrl) {
      normalizedUrl = formUrl;
      if (!normalizedUrl.startsWith('http://') && !normalizedUrl.startsWith('https://')) {
        normalizedUrl = 'https://' + normalizedUrl;
      }

      try {
        new URL(normalizedUrl);
        if (!normalizedUrl.includes('.')) throw new Error('Invalid domain');
      } catch {
        e.target.elements.url.setCustomValidity('Please enter a valid URL or domain.');
        e.target.elements.url.reportValidity();
        return;
      }

      e.target.elements.url.value = normalizedUrl;
    }

    if (isUrlRequired && !normalizedUrl) {
      e.target.elements.url.setCustomValidity('Website URL is required for security and bug reports.');
      e.target.elements.url.reportValidity();
      return;
    }

    setIsSubmitting(true);

    const formData = new FormData(e.target);
    const data = {
      form_type: 'unified',
      topic: topic,
      email: formData.get('email') || '',
      message: formData.get('message') || '',
      url: normalizedUrl
    };

    try {
      const response = await fetch('/api/contact', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(data)
      });

      const result = await response.json();
      if (!response.ok) throw new Error(result.error || 'Failed to submit the form');

      setSubmitSuccess(true);
    } catch (err) {
      setSubmitError(err.message || 'An error occurred during submission.');
    } finally {
      setIsSubmitting(false);
    }
  };

  return (
    <div className="contact-page flex flex-col min-h-screen font-sans relative overflow-hidden" style={{ backgroundColor: '#070B14' }}>

      {/* Ambient Glows */}
      <div className="absolute top-0 left-1/2 -translate-x-1/2 w-full max-w-4xl h-[500px] opacity-30 pointer-events-none">
        <div className="absolute inset-0 bg-indigo-500/20 blur-[120px] rounded-full mix-blend-screen" />
        <div className="absolute top-1/4 left-1/4 w-1/2 h-1/2 bg-violet-600/20 blur-[100px] rounded-full mix-blend-screen" />
      </div>

      <div className="relative max-w-2xl mx-auto px-4 sm:px-6 py-20 w-full z-10 flex flex-col items-center">

        {/* Header */}
        <header className="mb-10 text-center flex flex-col items-center">
          <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-indigo-500/10 border border-indigo-500/20 text-indigo-400 text-xs font-bold tracking-wider mb-6">
            ✦ GET IN TOUCH
          </div>
          <h1 className="text-4xl md:text-5xl font-bold text-white mb-4 tracking-tight">
            Contact Us
          </h1>
          <div className="text-lg text-slate-400 max-w-lg space-y-2">
            <p>Have questions or need assistance? Fill out the form below or reach us directly at <a href="mailto:contact@urlscanonline.com" className="font-medium text-indigo-400 hover:underline underline-offset-2">contact@urlscanonline.com</a>.</p>
          </div>
        </header>

        {/* Glassmorphism Card */}
        <div className="contact-card w-full bg-slate-900/60 backdrop-blur-xl border border-white/10 rounded-2xl shadow-2xl p-6 sm:p-10">
          {submitSuccess ? (
            <div className="text-center py-10 animate-in fade-in zoom-in duration-500">
              <div className="w-16 h-16 bg-emerald-500/10 rounded-full flex items-center justify-center text-emerald-500 mx-auto mb-6 ring-1 ring-emerald-500/20 shadow-[0_0_30px_rgba(16,185,129,0.1)]">
                <CheckCircle2 className="w-8 h-8" />
              </div>
              <h3 className="text-2xl font-bold text-white mb-3">Message Sent</h3>
              <p className="text-slate-400 mb-8 max-w-sm mx-auto leading-relaxed">
                Thank you for reaching out! We have received your message and will get back to you shortly.
              </p>
              <button
                onClick={() => setSubmitSuccess(false)}
                className="text-indigo-400 hover:text-indigo-300 font-medium text-sm transition-colors hover:underline underline-offset-4"
              >
                Send another message
              </button>
            </div>
          ) : (
            <form onSubmit={handleSubmit} className="space-y-6">
              {submitError && (
                <div className="p-4 bg-rose-500/10 border border-rose-500/20 rounded-xl text-rose-400 text-sm flex items-start gap-3">
                  <AlertTriangle className="w-5 h-5 shrink-0" />
                  <p>{submitError}</p>
                </div>
              )}

              <div className="space-y-2">
                <label htmlFor="topic" className="contact-label block text-sm font-medium text-slate-300">
                  Topic <span className="text-rose-400">*</span>
                </label>
                <div className="relative">
                  <select
                    id="topic"
                    name="topic"
                    value={topic}
                    onChange={handleTopicChange}
                    required
                    className="contact-input w-full bg-slate-950/60 border border-white/10 rounded-xl px-4 py-3 text-white focus:outline-none focus:ring-2 focus:ring-indigo-500/20 focus:border-indigo-500 transition-all appearance-none cursor-pointer"
                  >
                    <option value="General Question">General Question</option>
                    <option value="Security / Bug Report">Security / Bug Report</option>
                    <option value="Billing">Billing</option>
                    <option value="Partnership / Business Inquiry">Partnership / Business Inquiry</option>
                  </select>
                  <div className="absolute inset-y-0 right-4 flex items-center pointer-events-none text-slate-400">
                    <ChevronDown className="w-5 h-5" />
                  </div>
                </div>
              </div>

              <div className="space-y-2">
                <label htmlFor="email" className="contact-label block text-sm font-medium text-slate-300">
                  Email <span className="text-rose-400">*</span>
                </label>
                <input
                  id="email"
                  name="email"
                  type="email"
                  required
                  placeholder="you@example.com"
                  className="contact-input w-full bg-slate-950/60 border border-white/10 rounded-xl px-4 py-3 text-white focus:outline-none focus:ring-2 focus:ring-indigo-500/20 focus:border-indigo-500 transition-all placeholder:text-slate-600"
                />
              </div>

              {isUrlRequired && (
                <div className="space-y-2 animate-in fade-in slide-in-from-top-2 duration-300">
                  <label htmlFor="url" className="contact-label block text-sm font-medium text-slate-300">
                    Website URL {isUrlRequired ? <span className="text-rose-400">*</span> : <span className="text-slate-500 font-normal">(optional)</span>}
                  </label>
                  <input
                    id="url"
                    name="url"
                    type="text"
                    required={isUrlRequired}
                    placeholder="https://example.com"
                    onChange={(e) => e.target.setCustomValidity('')}
                    className="contact-input w-full bg-slate-950/60 border border-white/10 rounded-xl px-4 py-3 text-white focus:outline-none focus:ring-2 focus:ring-indigo-500/20 focus:border-indigo-500 transition-all placeholder:text-slate-600"
                  />
                  {isUrlRequired && (
                    <p className="text-xs text-slate-500 mt-1.5">Required to investigate security issues or bug reports.</p>
                  )}
                </div>
              )}

              <div className="space-y-2">
                <label htmlFor="message" className="contact-label block text-sm font-medium text-slate-300">
                  Message <span className="text-rose-400">*</span>
                </label>
                <textarea
                  id="message"
                  name="message"
                  required
                  rows="4"
                  placeholder="How can we help?"
                  className="contact-input w-full bg-slate-950/60 border border-white/10 rounded-xl px-4 py-3 text-white focus:outline-none focus:ring-2 focus:ring-indigo-500/20 focus:border-indigo-500 transition-all resize-none placeholder:text-slate-600"
                ></textarea>
              </div>

              <button
                type="submit"
                disabled={isSubmitting}
                className="w-full relative group overflow-hidden flex items-center justify-center px-6 py-3.5 bg-gradient-to-r from-indigo-500 to-violet-600 hover:from-indigo-400 hover:to-violet-500 disabled:opacity-50 disabled:cursor-not-allowed text-white font-semibold rounded-xl transition-all shadow-lg shadow-indigo-500/25"
                style={{ color: '#ffffff' }}
              >
                <span className="relative z-10 flex items-center gap-2">
                  {isSubmitting ? 'Sending...' : 'Send Message →'}
                </span>
                <div className="absolute inset-0 -translate-x-full group-hover:animate-[shimmer_1.5s_infinite] bg-gradient-to-r from-transparent via-white/10 to-transparent z-0" />
              </button>
            </form>
          )}
        </div>

        <div className="mt-8 text-center flex flex-col items-center">
          <p className="text-slate-400 mb-8 max-w-lg text-center">
            We typically respond within 1–2 business days.
          </p>
          <button
            onClick={handleBack}
            className="inline-flex items-center text-sm text-slate-500 hover:text-slate-300 transition-colors font-medium group"
          >
            <ArrowLeft className="w-4 h-4 mr-2 group-hover:-translate-x-1 transition-transform" />
            Back
          </button>
        </div>

      </div>
    </div>
  );
};

export default Contact;
