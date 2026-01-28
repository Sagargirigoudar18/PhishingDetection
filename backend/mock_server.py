from http.server import HTTPServer, BaseHTTPRequestHandler
import json
import random
from datetime import datetime
import urllib.parse

class MockAPIHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == '/':
            self.send_response(200)
            self.send_header('Content-type', 'application/json')
            self.end_headers()
            response = {"message": "PhishShield API is running", "version": "1.0.0"}
            self.wfile.write(json.dumps(response).encode())
            
        elif self.path == '/health':
            self.send_response(200)
            self.send_header('Content-type', 'application/json')
            self.end_headers()
            response = {"status": "healthy", "timestamp": datetime.utcnow().isoformat()}
            self.wfile.write(json.dumps(response).encode())
            
        else:
            self.send_response(404)
            self.end_headers()
    
    def do_POST(self):
        if self.path == '/api/detect/analyze':
            # Read the request body
            content_length = int(self.headers['Content-Length'])
            post_data = self.rfile.read(content_length)
            
            try:
                data = json.loads(post_data.decode('utf-8'))
                content = data.get('content', '').lower()
                content_type = data.get('content_type', 'text')
                
                # Simple mock detection logic
                suspicious_keywords = ['urgent', 'verify', 'account', 'suspended', 'click', 'password', 'bank', 'paypal']
                keyword_count = sum(1 for word in suspicious_keywords if word in content)
                
                # Calculate mock risk score
                risk_score = min(keyword_count * 0.2 + random.uniform(0, 0.3), 1.0)
                is_phishing = risk_score > 0.5
                
                # Determine risk level
                if risk_score >= 0.7:
                    risk_level = "HIGH"
                elif risk_score >= 0.4:
                    risk_level = "MEDIUM"
                else:
                    risk_level = "LOW"
                
                # Generate explanation
                if is_phishing:
                    explanation = f"This message contains suspicious elements and shows characteristics commonly found in phishing attempts. Found {keyword_count} suspicious keywords."
                    recommendations = [
                        "Do not click on any links or download attachments",
                        "Do not provide personal or financial information",
                        "Report this as phishing to your IT department",
                        "Delete the message immediately"
                    ]
                else:
                    explanation = "This message appears to be legitimate based on our analysis. However, always remain cautious with unexpected messages."
                    recommendations = [
                        "Remain vigilant for suspicious requests",
                        "Verify unexpected messages through official channels",
                        "Keep your security software updated"
                    ]
                
                response = {
                    "is_phishing": is_phishing,
                    "confidence": round(risk_score, 2),
                    "risk_level": risk_level,
                    "explanation": explanation,
                    "recommendations": recommendations,
                    "timestamp": datetime.utcnow().isoformat(),
                    "content_type": content_type
                }
                
                self.send_response(200)
                self.send_header('Content-type', 'application/json')
                self.send_header('Access-Control-Allow-Origin', '*')
                self.send_header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
                self.send_header('Access-Control-Allow-Headers', 'Content-Type')
                self.end_headers()
                self.wfile.write(json.dumps(response).encode())
                
            except Exception as e:
                self.send_response(500)
                self.send_header('Content-type', 'application/json')
                self.end_headers()
                error_response = {"error": str(e)}
                self.wfile.write(json.dumps(error_response).encode())
        else:
            self.send_response(404)
            self.end_headers()
    
    def do_OPTIONS(self):
        self.send_response(200)
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type')
        self.end_headers()

def run_server(port=8000):
    server_address = ('', port)
    httpd = HTTPServer(server_address, MockAPIHandler)
    print(f"🚀 Mock API server running at http://localhost:{port}")
    print("📝 This is a mock server for testing the frontend")
    print("🔗 Frontend can connect to this server")
    print("\nPress Ctrl+C to stop the server")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n🛑 Server stopped")

if __name__ == '__main__':
    run_server()
