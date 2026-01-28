import { ShieldCheckIcon, ShieldExclamationIcon, ExclamationTriangleIcon, InformationCircleIcon } from '@heroicons/react/24/outline';
import { useNavigate } from 'react-router-dom';

export function AnalysisResult({ result, error, isLoading }) {
  const navigate = useNavigate();
  
  const getRiskLevelConfig = (riskLevel) => {
    switch (riskLevel?.toLowerCase()) {
      case 'high':
        return {
          icon: ShieldExclamationIcon,
          bgColor: 'bg-red-100',
          textColor: 'text-red-800',
          borderColor: 'border-red-200',
          title: 'High Risk - Likely Phishing',
          description: 'This content shows strong signs of being a phishing attempt.'
        };
      case 'medium':
        return {
          icon: ExclamationTriangleIcon,
          bgColor: 'bg-yellow-100',
          textColor: 'text-yellow-800',
          borderColor: 'border-yellow-200',
          title: 'Suspicious',
          description: 'This content shows some characteristics of phishing. Proceed with caution.'
        };
      case 'low':
      default:
        return {
          icon: ShieldCheckIcon,
          bgColor: 'bg-green-100',
          textColor: 'text-green-800',
          borderColor: 'border-green-200',
          title: 'Low Risk - Likely Safe',
          description: 'This content appears to be safe, but always stay vigilant.'
        };
    }
  };

  const riskConfig = result?.risk_level ? getRiskLevelConfig(result.risk_level) : getRiskLevelConfig('low');
  const RiskIcon = riskConfig.icon;

  if (isLoading) {
    return (
      <div className="text-center py-12">
        <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-blue-500 mx-auto"></div>
        <p className="mt-4 text-gray-600">Analyzing content for phishing indicators...</p>
      </div>
    );
  }

  if (error || !result) {
    return (
      <div className="bg-white rounded-lg shadow overflow-hidden">
        <div className="p-6">
          <div className="bg-red-50 border-l-4 border-red-400 p-4 mb-6">
            <div className="flex">
              <div className="flex-shrink-0">
                <ShieldExclamationIcon className="h-5 w-5 text-red-400" />
              </div>
              <div className="ml-3">
                <p className="text-sm text-red-700">
                  {error || 'No analysis results available. Please try again.'}
                </p>
              </div>
            </div>
          </div>
          <button
            onClick={() => navigate('/')}
            className="inline-flex items-center px-4 py-2 border border-transparent text-sm font-medium rounded-md shadow-sm text-white bg-blue-600 hover:bg-blue-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-blue-500"
          >
            Back to Home
          </button>
        </div>
      </div>
    );
  }

  return (
    <div className="max-w-4xl mx-auto">
      <div className="bg-white rounded-xl shadow-md overflow-hidden">
        {/* Result Header */}
        <div className={`${riskConfig.bgColor} px-6 py-4 border-b ${riskConfig.borderColor}`}>
          <div className="flex items-center">
            <div className="flex-shrink-0">
              <RiskIcon className={`h-8 w-8 ${riskConfig.textColor}`} />
            </div>
            <div className="ml-4">
              <h2 className={`text-xl font-semibold ${riskConfig.textColor}`}>
                {riskConfig.title}
              </h2>
              <p className="text-sm text-gray-700">
                {riskConfig.description}
              </p>
            </div>
          </div>
        </div>

        {/* Confidence Score */}
        <div className="p-6 border-b border-gray-200">
          <div className="flex items-center justify-between mb-2">
            <span className="text-sm font-medium text-gray-700">Confidence</span>
            <span className="text-sm font-semibold text-gray-900">
              {Math.round((result.confidence || 0) * 100)}%
            </span>
          </div>
          <div className="w-full bg-gray-200 rounded-full h-2.5">
            <div 
              className={`h-2.5 rounded-full ${riskConfig.bgColor.replace('100', '500')}`}
              style={{ width: `${(result.confidence || 0) * 100}%` }}
            ></div>
          </div>
        </div>

        {/* Explanation */}
        {result.explanation && (
          <div className="p-6 border-b border-gray-200">
            <h3 className="text-lg font-medium text-gray-900 mb-3">Analysis</h3>
            <div className="bg-blue-50 border-l-4 border-blue-400 p-4">
              <div className="flex">
                <div className="flex-shrink-0">
                  <InformationCircleIcon className="h-5 w-5 text-blue-400" />
                </div>
                <div className="ml-3">
                  <p className="text-sm text-blue-700">
                    {result.explanation}
                  </p>
                </div>
              </div>
            </div>
          </div>
        )}

        {/* Recommendations */}
        {result.recommendations?.length > 0 && (
          <div className="p-6">
            <h3 className="text-lg font-medium text-gray-900 mb-3">Recommended Actions</h3>
            <ul className="space-y-2">
              {result.recommendations.map((rec, index) => (
                <li key={index} className="flex items-start">
                  <div className="flex-shrink-0 h-5 w-5 text-blue-500 mt-0.5">
                    <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 20 20" fill="currentColor">
                      <path fillRule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zm3.707-9.293a1 1 0 00-1.414-1.414L9 10.586 7.707 9.293a1 1 0 00-1.414 1.414l2 2a1 1 0 001.414 0l4-4z" clipRule="evenodd" />
                    </svg>
                  </div>
                  <span className="ml-2 text-gray-700">{rec}</span>
                </li>
              ))}
            </ul>
          </div>
        )}

        {/* Actions */}
        <div className="bg-gray-50 px-6 py-4 flex justify-between">
          <button
            onClick={() => navigate('/')}
            className="inline-flex items-center px-4 py-2 border border-gray-300 shadow-sm text-sm font-medium rounded-md text-gray-700 bg-white hover:bg-gray-50 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-blue-500"
          >
            Analyze Another
          </button>
          
          <div className="space-x-3">
            <button className="inline-flex items-center px-4 py-2 border border-transparent text-sm font-medium rounded-md shadow-sm text-white bg-blue-600 hover:bg-blue-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-blue-500">
              Report as Incorrect
            </button>
            <button className="inline-flex items-center px-4 py-2 border border-transparent text-sm font-medium rounded-md shadow-sm text-white bg-green-600 hover:bg-green-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-green-500">
              Learn More
            </button>
          </div>
        </div>
      </div>

      {/* Additional Information */}
      <div className="mt-8 bg-white rounded-lg shadow overflow-hidden">
        <div className="p-6">
          <h3 className="text-lg font-medium text-gray-900 mb-4">How to Stay Safe</h3>
          <div className="grid gap-4 md:grid-cols-2">
            <div className="p-4 bg-gray-50 rounded-lg">
              <h4 className="font-medium text-gray-900 mb-2">For Emails</h4>
              <ul className="text-sm text-gray-600 space-y-1">
                <li>• Verify sender email addresses carefully</li>
                <li>• Hover over links before clicking</li>
                <li>• Don't download attachments from unknown senders</li>
              </ul>
            </div>
            <div className="p-4 bg-gray-50 rounded-lg">
              <h4 className="font-medium text-gray-900 mb-2">For Messages</h4>
              <ul className="text-sm text-gray-600 space-y-1">
                <li>• Be wary of urgent requests for personal info</li>
                <li>• Don't respond to requests for passwords or PINs</li>
                <li>• Verify suspicious messages through official channels</li>
              </ul>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
