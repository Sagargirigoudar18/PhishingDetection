import { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { ShieldExclamationIcon, EnvelopeIcon, LinkIcon, ChatBubbleLeftRightIcon } from '@heroicons/react/24/outline';

export function Home({ analyzeContent, isLoading, error }) {
  const [content, setContent] = useState('');
  const [contentType, setContentType] = useState('email');
  const navigate = useNavigate();

  const handleSubmit = async (e) => {
    e.preventDefault();
    if (!content.trim()) return;
    
    const result = await analyzeContent(content, contentType);
    if (result) {
      navigate('/result');
    }
  };

  const handlePaste = (e) => {
    const pastedText = e.clipboardData.getData('text/plain');
    if (pastedText.startsWith('http://') || pastedText.startsWith('https://')) {
      setContentType('url');
    } else if (pastedText.includes('@') && pastedText.includes('.')) {
      setContentType('email');
    } else if (pastedText.length < 160) {
      setContentType('sms');
    }
  };

  const getContentTypeIcon = () => {
    switch (contentType) {
      case 'email':
        return <EnvelopeIcon className="h-5 w-5 text-gray-500" />;
      case 'url':
        return <LinkIcon className="h-5 w-5 text-blue-500" />;
      case 'sms':
      case 'whatsapp':
        return <ChatBubbleLeftRightIcon className="h-5 w-5 text-green-500" />;
      default:
        return <ShieldExclamationIcon className="h-5 w-5 text-gray-400" />;
    }
  };

  return (
    <div className="max-w-4xl mx-auto">
      <div className="text-center mb-12">
        <h1 className="text-4xl font-bold text-gray-900 mb-4">Phishing Detection System</h1>
        <p className="text-lg text-gray-600">
          Analyze emails, messages, and URLs for potential phishing attempts
        </p>
      </div>

      <div className="bg-white rounded-xl shadow-md overflow-hidden">
        <div className="p-6">
          <form onSubmit={handleSubmit}>
            <div className="mb-6">
              <div className="flex items-center justify-between mb-2">
                <label htmlFor="content" className="block text-sm font-medium text-gray-700">
                  Enter content to analyze
                </label>
                <div className="relative">
                  <select
                    value={contentType}
                    onChange={(e) => setContentType(e.target.value)}
                    className="appearance-none bg-white border border-gray-300 rounded-md pl-3 pr-8 py-1 text-sm focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-blue-500"
                  >
                    <option value="email">Email</option>
                    <option value="sms">SMS</option>
                    <option value="whatsapp">WhatsApp</option>
                    <option value="url">URL</option>
                  </select>
                  <div className="pointer-events-none absolute inset-y-0 right-0 flex items-center px-2 text-gray-700">
                    <svg className="fill-current h-4 w-4" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 20 20">
                      <path d="M9.293 12.95l.707.707L15.657 8l-1.414-1.414L10 10.828 5.757 6.586 4.343 8z" />
                    </svg>
                  </div>
                </div>
              </div>
              
              <div className="mt-1 relative rounded-md shadow-sm">
                <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none">
                  {getContentTypeIcon()}
                </div>
                <textarea
                  id="content"
                  name="content"
                  rows={8}
                  className="focus:ring-blue-500 focus:border-blue-500 block w-full pl-10 sm:text-sm border border-gray-300 rounded-md p-3"
                  placeholder={
                    contentType === 'url' 
                      ? 'https://example.com/suspicious-link' 
                      : `Paste ${contentType === 'email' ? 'email content' : 'message content'} here...`
                  }
                  value={content}
                  onChange={(e) => setContent(e.target.value)}
                  onPaste={handlePaste}
                  disabled={isLoading}
                />
              </div>
              
              <p className="mt-2 text-sm text-gray-500">
                {contentType === 'url' 
                  ? 'Enter a URL to check for phishing indicators.'
                  : `Paste the ${contentType} content you want to analyze.`}
              </p>
            </div>

            <div className="flex justify-end">
              <button
                type="submit"
                disabled={!content.trim() || isLoading}
                className={`inline-flex items-center px-6 py-3 border border-transparent text-base font-medium rounded-md shadow-sm text-white ${
                  !content.trim() || isLoading
                    ? 'bg-blue-300 cursor-not-allowed'
                    : 'bg-blue-600 hover:bg-blue-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-blue-500'
                }`}
              >
                {isLoading ? (
                  <>
                    <svg className="animate-spin -ml-1 mr-3 h-5 w-5 text-white" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24">
                      <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"></circle>
                      <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
                    </svg>
                    Analyzing...
                  </>
                ) : (
                  'Analyze for Phishing'
                )}
              </button>
            </div>
          </form>
        </div>
      </div>

      {error && (
        <div className="mt-6 bg-red-50 border-l-4 border-red-400 p-4">
          <div className="flex">
            <div className="flex-shrink-0">
              <svg className="h-5 w-5 text-red-400" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 20 20" fill="currentColor">
                <path fillRule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zM8.707 7.293a1 1 0 00-1.414 1.414L8.586 10l-1.293 1.293a1 1 0 101.414 1.414L10 11.414l1.293 1.293a1 1 0 001.414-1.414L11.414 10l1.293-1.293a1 1 0 00-1.414-1.414L10 8.586 8.707 7.293z" clipRule="evenodd" />
              </svg>
            </div>
            <div className="ml-3">
              <p className="text-sm text-red-700">{error}</p>
            </div>
          </div>
        </div>
      )}

      <div className="mt-12 grid gap-6 md:grid-cols-3">
        <div className="bg-white p-6 rounded-lg shadow">
          <div className="flex items-center mb-3">
            <div className="flex-shrink-0 flex items-center justify-center h-10 w-10 rounded-md bg-blue-100 text-blue-600">
              <ShieldExclamationIcon className="h-6 w-6" />
            </div>
            <h3 className="ml-3 text-lg font-medium text-gray-900">Email Protection</h3>
          </div>
          <p className="text-gray-600 text-sm">
            Detect phishing attempts in emails, including suspicious links and requests for personal information.
          </p>
        </div>

        <div className="bg-white p-6 rounded-lg shadow">
          <div className="flex items-center mb-3">
            <div className="flex-shrink-0 flex items-center justify-center h-10 w-10 rounded-md bg-green-100 text-green-600">
              <ChatBubbleLeftRightIcon className="h-6 w-6" />
            </div>
            <h3 className="ml-3 text-lg font-medium text-gray-900">SMS & WhatsApp</h3>
          </div>
          <p className="text-gray-600 text-sm">
            Analyze text messages and WhatsApp conversations for potential smishing attempts and scams.
          </p>
        </div>

        <div className="bg-white p-6 rounded-lg shadow">
          <div className="flex items-center mb-3">
            <div className="flex-shrink-0 flex items-center justify-center h-10 w-10 rounded-md bg-purple-100 text-purple-600">
              <LinkIcon className="h-6 w-6" />
            </div>
            <h3 className="ml-3 text-lg font-medium text-gray-900">URL Analysis</h3>
          </div>
          <p className="text-gray-600 text-sm">
            Check any URL for signs of phishing, including domain age, SSL status, and suspicious patterns.
          </p>
        </div>
      </div>
    </div>
  );
}
