import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { Mail, AlertTriangle, CheckCircle2, ArrowLeft } from 'lucide-react';

const Contact = () => {
  const navigate = useNavigate();
  const [submitSuccess, setSubmitSuccess] = useState(false);
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [submitError, setSubmitError] = useState('');
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

  const handleSubmit = async (e) => {
    e.preventDefault();
    setSubmitError('');

    let normalizedUrl = '';
    const formUrl = e.target.elements.url?.value?.trim() || '';

    // If a URL is provided, validate and normalize it
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

      e.target.elements.url.value = normalizedUrl; // Update input with normalized URL
    }

    // Require URL for False Positives
    if (topic === 'Report a False Positive' && !normalizedUrl) {
      e.target.elements.url.setCustomValidity('Website URL is required to report a false positive.');
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
    <div className="flex flex-col min-h-screen bg-slate-950 text-slate-200 font-sans">
      <div className="max-w-3xl mx-auto px-4 sm:px-6 lg:px-8 py-12 w-full">

        {/* Header */}
        <header className="mb-12 text-center md:text-left">
          <h1 className="text-3xl md:text-5xl font-black text-slate-50 mb-4 tracking-tight">
            Contact Us
          </h1>
          <p className="text-lg text-slate-400">
            We typically respond within 1–2 business days. Send us a message below.
          </p>
        </header>

        <div className="bg-slate-900 border border-slate-800 rounded-2xl overflow-hidden p-6 md:p-8">
          {submitSuccess ? (
            <div className="text-center py-12">
              <div className="w-16 h-16 bg-emerald-500/10 rounded-full flex items-center justify-center text-emerald-500 mx-auto mb-4">
                <CheckCircle2 className="w-8 h-8" />
              </div>
              <h3 className="text-xl font-bold text-slate-50 mb-2">Message Sent</h3>
              <p className="text-slate-400 mb-6 max-w-sm mx-auto">
                Thank you for reaching out! We have received your message and will get back to you shortly.
              </p>
              <button
                onClick={() => setSubmitSuccess(false)}
                className="text-indigo-400 hover:text-indigo-300 font-medium text-sm"
              >
                Send another message
              </button>
            </div>
          ) : (
            <form onSubmit={handleSubmit} className="space-y-6">
              {submitError && (
                <div className="p-4 bg-red-500/10 border border-red-500/50 rounded-lg text-red-400 text-sm">
                  {submitError}
                </div>
              )}

              <div className="space-y-2">
                <label htmlFor="topic" className="text-sm font-medium text-slate-300">Topic *</label>
                <select
                  id="topic"
                  name="topic"
                  value={topic}
                  onChange={handleTopicChange}
                  required
                  className="w-full bg-slate-950 border border-slate-800 rounded-lg px-4 py-2.5 text-slate-200 focus:outline-none focus:border-indigo-500 focus:ring-1 focus:ring-indigo-500 transition-colors appearance-none"
                >
                  <option value="General Question">General Question</option>
                  <option value="Technical Support">Technical Support</option>
                  <option value="Partnership / Business Inquiry">Partnership / Business Inquiry</option>
                  <option value="Report a False Positive">Report a False Positive</option>
                  <option value="Other">Other</option>
                </select>
              </div>

              <div className="space-y-2">
                <label htmlFor="email" className="text-sm font-medium text-slate-300">Email *</label>
                <input
                  id="email"
                  name="email"
                  type="email"
                  required
                  placeholder="jane@example.com"
                  className="w-full bg-slate-950 border border-slate-800 rounded-lg px-4 py-2.5 text-slate-200 focus:outline-none focus:border-indigo-500 focus:ring-1 focus:ring-indigo-500 transition-colors"
                />
              </div>

              {(topic === 'Report a False Positive' || topic === 'Technical Support') && (
                <div className="space-y-2">
                  <label htmlFor="url" className="text-sm font-medium text-slate-300">
                    Website URL {topic === 'Report a False Positive' ? '*' : <span className="text-slate-600">(optional)</span>}
                  </label>
                  <input
                    id="url"
                    name="url"
                    type="text"
                    required={topic === 'Report a False Positive'}
                    placeholder="https://example.com"
                    onChange={(e) => e.target.setCustomValidity('')}
                    className="w-full bg-slate-950 border border-slate-800 rounded-lg px-4 py-2.5 text-slate-200 focus:outline-none focus:border-indigo-500 focus:ring-1 focus:ring-indigo-500 transition-colors"
                  />
                  {topic === 'Report a False Positive' && (
                    <p className="text-xs text-slate-500">Please provide the URL related to the false positive.</p>
                  )}
                </div>
              )}

              <div className="space-y-2">
                <label htmlFor="message" className="text-sm font-medium text-slate-300">Message *</label>
                <textarea
                  id="message"
                  name="message"
                  required
                  rows="5"
                  placeholder="How can we help?"
                  className="w-full bg-slate-950 border border-slate-800 rounded-lg px-4 py-2.5 text-slate-200 focus:outline-none focus:border-indigo-500 focus:ring-1 focus:ring-indigo-500 transition-colors resize-none"
                ></textarea>
              </div>

              <button
                type="submit"
                disabled={isSubmitting}
                className="w-full flex items-center justify-center px-6 py-3 bg-indigo-600 hover:bg-indigo-500 disabled:opacity-50 disabled:cursor-not-allowed text-white font-medium rounded-lg transition-colors shadow-lg shadow-indigo-600/20"
              >
                {isSubmitting ? 'Sending...' : 'Send Message'}
              </button>
            </form>
          )}
        </div>

        <div className="mt-12 text-center">
          <button
            onClick={handleBack}
            className="inline-flex items-center text-slate-400 hover:text-slate-200 transition-colors font-medium"
          >
            <ArrowLeft size={16} className="mr-2" />
            Back
          </button>
        </div>

      </div>
    </div>
  );
};

export default Contact;
