// Global variables
let selectedDetectionType = null;
let currentPage = 'home';
const API_BASE_URL = 'http://localhost:8080';

// Initialize the application
document.addEventListener('DOMContentLoaded', function() {
    // Set default page
    showPage('home');
    
    // Test API connection on load
    testAPIConnection();
});

// Test API connection
async function testAPIConnection() {
    const statusIcon = document.getElementById('status-icon');
    const statusText = document.getElementById('status-text');
    const connectionStatus = document.getElementById('connection-status');
    
    // Set checking status
    statusIcon.className = 'fas fa-circle text-yellow-500 text-xs';
    statusText.textContent = 'Checking...';
    connectionStatus.className = 'flex items-center space-x-2 px-3 py-1 rounded-full bg-yellow-100';
    
    try {
        console.log('Testing connection to:', `${API_BASE_URL}/health`);
        const response = await fetch(`${API_BASE_URL}/health`, {
            method: 'GET',
            headers: {
                'Content-Type': 'application/json',
            },
            mode: 'cors'
        });
        
        console.log('Response status:', response.status);
        console.log('Response ok:', response.ok);
        
        if (response.ok) {
            const data = await response.json();
            console.log('✅ Backend API is connected:', data);
            statusIcon.className = 'fas fa-circle text-green-500 text-xs';
            statusText.textContent = 'Connected';
            connectionStatus.className = 'flex items-center space-x-2 px-3 py-1 rounded-full bg-green-100';
            showNotification('Backend connected successfully', 'success');
        } else {
            console.warn('⚠️ Backend API responded with error:', response.status);
            statusIcon.className = 'fas fa-circle text-red-500 text-xs';
            statusText.textContent = 'Error';
            connectionStatus.className = 'flex items-center space-x-2 px-3 py-1 rounded-full bg-red-100';
            showNotification(`Backend API responded with status: ${response.status}`, 'warning');
        }
    } catch (error) {
        console.error('❌ Cannot connect to backend API:', error);
        statusIcon.className = 'fas fa-circle text-red-500 text-xs';
        statusText.textContent = 'Disconnected';
        connectionStatus.className = 'flex items-center space-x-2 px-3 py-1 rounded-full bg-red-100';
        showNotification(`Backend API is not running. Error: ${error.message}`, 'error');
    }
}

// Show notification
function showNotification(message, type = 'info') {
    // Create notification element
    const notification = document.createElement('div');
    notification.className = `fixed top-4 right-4 p-4 rounded-lg shadow-lg z-50 max-w-sm ${
        type === 'success' ? 'bg-green-500 text-white' :
        type === 'error' ? 'bg-red-500 text-white' :
        type === 'warning' ? 'bg-yellow-500 text-black' :
        'bg-blue-500 text-white'
    }`;
    notification.innerHTML = `
        <div class="flex items-center">
            <i class="fas ${
                type === 'success' ? 'fa-check-circle' :
                type === 'error' ? 'fa-exclamation-circle' :
                type === 'warning' ? 'fa-exclamation-triangle' :
                'fa-info-circle'
            } mr-2"></i>
            <span>${message}</span>
        </div>
    `;
    
    document.body.appendChild(notification);
    
    // Auto-remove after 5 seconds
    setTimeout(() => {
        notification.remove();
    }, 5000);
}

// Page navigation
function showPage(pageName) {
    // Hide all pages
    document.querySelectorAll('.page').forEach(page => {
        page.classList.remove('active');
    });
    
    // Show selected page
    const selectedPage = document.getElementById(`${pageName}-page`);
    if (selectedPage) {
        selectedPage.classList.add('active');
        currentPage = pageName;
    }
    
    // Update navigation active state
    document.querySelectorAll('.nav-link').forEach(link => {
        link.classList.remove('active');
        if (link.getAttribute('data-page') === pageName) {
            link.classList.add('active');
        }
    });
    
    // Hide results section when switching pages
    document.getElementById('results-section').classList.add('hidden');
    
    // Scroll to top
    window.scrollTo({ top: 0, behavior: 'smooth' });
}

// Get content based on selected type
function getContent() {
    let content = '';
    let metadata = {};
    
    switch(selectedDetectionType) {
        case 'email':
            const emailFrom = document.getElementById('email-from').value;
            const emailSubject = document.getElementById('email-subject').value;
            const emailContent = document.getElementById('email-content').value;
            
            content = `From: ${emailFrom}\nSubject: ${emailSubject}\n\n${emailContent}`;
            metadata = {
                from: emailFrom,
                subject: emailSubject
            };
            break;
            
        case 'sms':
            const smsFrom = document.getElementById('sms-from').value;
            const smsContent = document.getElementById('sms-content').value;
            
            content = `From: ${smsFrom}\n\n${smsContent}`;
            metadata = {
                from: smsFrom
            };
            break;
            
        case 'whatsapp':
            const whatsappFrom = document.getElementById('whatsapp-from').value;
            const whatsappContent = document.getElementById('whatsapp-content').value;
            
            content = `From: ${whatsappFrom}\n\n${whatsappContent}`;
            metadata = {
                from: whatsappFrom
            };
            break;
            
        case 'url':
            content = document.getElementById('url-content').value;
            break;
    }
    
    return { content, metadata };
}

// Validate input
function validateInput() {
    const { content } = getContent();
    
    if (!content || content.trim().length === 0) {
        alert('Please enter content to analyze');
        return false;
    }
    
    if (selectedDetectionType === 'url') {
        const urlPattern = /^https?:\/\/.+/;
        if (!urlPattern.test(content.trim())) {
            alert('Please enter a valid URL starting with http:// or https://');
            return false;
        }
    }
    
    return true;
}

// Show loading
function showLoading() {
    document.getElementById('loading-overlay').classList.remove('hidden');
    document.getElementById('analyze-btn').disabled = true;
    document.getElementById('analyze-btn-text').textContent = 'Analyzing...';
}

// Hide loading
function hideLoading() {
    document.getElementById('loading-overlay').classList.add('hidden');
    document.getElementById('analyze-btn').disabled = false;
    document.getElementById('analyze-btn-text').textContent = 'Analyze for Phishing';
}

// Analyze content
async function analyzeContent(type) {
    selectedDetectionType = type;
    
    if (!validateInput()) {
        return;
    }
    
    const { content, metadata } = getContent();
    
    showLoading();
    
    try {
        const response = await fetch(`${API_BASE_URL}/api/detect/analyze`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({
                content: content.trim(),
                content_type: selectedDetectionType,
                metadata: metadata
            })
        });
        
        if (!response.ok) {
            throw new Error(`HTTP error! status: ${response.status}`);
        }
        
        const result = await response.json();
        displayResults(result);
        
    } catch (error) {
        console.error('Error:', error);
        showNotification('Error analyzing content. Please make sure the backend server is running on http://localhost:8000', 'error');
    } finally {
        hideLoading();
    }
}

// Display results
function displayResults(result) {
    // Hide all pages, show results
    document.querySelectorAll('.page').forEach(page => {
        page.classList.remove('active');
    });
    document.getElementById('results-section').classList.remove('hidden');
    
    // Update risk score
    const riskPercentage = Math.round(result.confidence * 100);
    document.getElementById('risk-percentage').textContent = `${riskPercentage}%`;
    
    // Update risk bar
    const riskBar = document.getElementById('risk-bar');
    riskBar.style.width = `${riskPercentage}%`;
    
    // Update risk bar color based on level
    riskBar.className = 'h-4 rounded-full transition-all duration-500';
    if (result.risk_level === 'HIGH') {
        riskBar.classList.add('bg-red-500');
    } else if (result.risk_level === 'MEDIUM') {
        riskBar.classList.add('bg-yellow-500');
    } else {
        riskBar.classList.add('bg-green-500');
    }
    
    // Update verdict
    const verdict = document.getElementById('verdict');
    const verdictIcon = document.getElementById('verdict-icon');
    const verdictTitle = document.getElementById('verdict-title');
    const verdictDescription = document.getElementById('verdict-description');
    
    verdict.className = 'p-6 rounded-lg mb-6';
    if (result.is_phishing) {
        verdict.classList.add('bg-red-50', 'border', 'border-red-200');
        verdictIcon.className = 'fas fa-exclamation-triangle text-3xl mr-4 text-red-600';
        verdictTitle.textContent = '⚠️ PHISHING DETECTED';
        verdictTitle.className = 'text-xl font-bold mb-2 text-red-800';
        verdictDescription.textContent = `This ${selectedDetectionType} shows strong signs of being a phishing attempt with ${riskPercentage}% confidence.`;
    } else {
        verdict.classList.add('bg-green-50', 'border', 'border-green-200');
        verdictIcon.className = 'fas fa-check-circle text-3xl mr-4 text-green-600';
        verdictTitle.textContent = '✅ APPEARS SAFE';
        verdictTitle.className = 'text-xl font-bold mb-2 text-green-800';
        verdictDescription.textContent = `This ${selectedDetectionType} appears to be legitimate with ${100 - riskPercentage}% safety confidence.`;
    }
    
    // Update explanation
    document.getElementById('explanation').textContent = result.explanation;
    
    // Update recommendations
    const recommendationsList = document.getElementById('recommendations');
    recommendationsList.innerHTML = '';
    result.recommendations.forEach(rec => {
        const li = document.createElement('li');
        li.className = 'flex items-start';
        li.innerHTML = `
            <i class="fas fa-shield-alt text-green-600 mt-1 mr-3 flex-shrink-0"></i>
            <span class="text-gray-700">${rec}</span>
        `;
        recommendationsList.appendChild(li);
    });
    
    // Add to history (simulate)
    addToDetectionHistory(selectedDetectionType, result);
    
    // Scroll to results
    document.getElementById('results-section').scrollIntoView({ behavior: 'smooth' });
}

// Reset form
function resetForm() {
    // Hide results, show home page
    showPage('home');
    
    // Clear all inputs
    document.querySelectorAll('input, textarea').forEach(input => {
        input.value = '';
    });
    
    // Scroll to top
    window.scrollTo({ top: 0, behavior: 'smooth' });
}

// Add to detection history (simulation)
function addToDetectionHistory(type, result) {
    // This would normally save to a database
    // For now, we'll just update the dashboard display
    console.log(`Added ${type} detection to history:`, result);
}

// Add keyboard shortcuts
document.addEventListener('keydown', function(e) {
    // Ctrl/Cmd + Enter to analyze
    if ((e.ctrlKey || e.metaKey) && e.key === 'Enter') {
        const analyzeBtn = document.getElementById('analyze-btn');
        if (!analyzeBtn.disabled) {
            analyzeContent();
        }
    }
    
    // Escape to reset
    if (e.key === 'Escape') {
        const resultsSection = document.getElementById('results-section');
        if (!resultsSection.classList.contains('hidden')) {
            resetForm();
        }
    }
});

// Add input validation
document.getElementById('url-content').addEventListener('input', function(e) {
    const url = e.target.value;
    const urlPattern = /^https?:\/\/.+/;
    
    if (url && !urlPattern.test(url)) {
        e.target.setCustomValidity('Please enter a valid URL starting with http:// or https://');
    } else {
        e.target.setCustomValidity('');
    }
});

// Add character counter for text areas
document.querySelectorAll('textarea').forEach(textarea => {
    const maxLength = 5000;
    textarea.addEventListener('input', function() {
        const remaining = maxLength - this.value.length;
        if (remaining < 500) {
            if (!this.nextElementSibling || !this.nextElementSibling.classList.contains('text-sm')) {
                const counter = document.createElement('div');
                counter.className = 'text-sm text-gray-500 mt-1';
                counter.textContent = `${remaining} characters remaining`;
                this.parentNode.insertBefore(counter, this.nextSibling);
            } else {
                this.nextElementSibling.textContent = `${remaining} characters remaining`;
            }
        }
    });
});
