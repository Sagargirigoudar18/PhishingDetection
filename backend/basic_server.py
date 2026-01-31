from http.server import HTTPServer, BaseHTTPRequestHandler
import json
from datetime import datetime
import urllib.parse

class PhishingAPIHandler(BaseHTTPRequestHandler):
    def do_OPTIONS(self):
        self.send_response(200)
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type')
        self.end_headers()

    def do_GET(self):
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Access-Control-Allow-Origin', '*')
        self.end_headers()
        
        if self.path == '/health':
            response = {
                "status": "healthy",
                "timestamp": datetime.utcnow().isoformat(),
                "version": "1.0.0"
            }
        else:
            response = {"message": "Phishing Detection API is running"}
        
        self.wfile.write(json.dumps(response).encode())

    def do_POST(self):
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Access-Control-Allow-Origin', '*')
        self.end_headers()
        
        content_length = int(self.headers['Content-Length'])
        post_data = self.rfile.read(content_length)
        
        try:
            request_data = json.loads(post_data.decode('utf-8'))
            content = request_data.get("content", "")
            content_type = request_data.get("content_type", "text")
            
            # Simple rule-based detection
            suspicious_keywords = ["urgent", "verify", "account", "suspended", "click", "password", "security"]
            is_phishing = any(keyword in content.lower() for keyword in suspicious_keywords)
            confidence = 0.8 if is_phishing else 0.2
            
            response = {
                "is_phishing": is_phishing,
                "confidence": confidence,
                "risk_level": "HIGH" if confidence > 0.6 else "LOW",
                "explanation": "This message contains suspicious keywords" if is_phishing else "This message appears safe",
                "recommendations": ["Do not click links", "Verify sender"] if is_phishing else ["Message appears safe"],
                "timestamp": datetime.utcnow().isoformat(),
                "content_type": content_type
            }
        except:
            response = {"error": "Invalid request"}
        
        self.wfile.write(json.dumps(response).encode())

    def log_message(self, format, *args):
        # Suppress default logging
        pass

if __name__ == "__main__":
    server_address = ('', 8080)
    httpd = HTTPServer(server_address, PhishingAPIHandler)
    print("🛡️ PhishShield Backend API running on http://localhost:8080")
    print("📖 Health endpoint: http://localhost:8080/health")
    print("🔍 Analysis endpoint: http://localhost:8080/api/detect/analyze")
    print("\nPress Ctrl+C to stop the server")
    
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n🛑 Server stopped")
        httpd.server_close()
