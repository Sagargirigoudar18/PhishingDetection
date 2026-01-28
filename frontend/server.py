import http.server
import socketserver
import os
import webbrowser
from pathlib import Path

# Set the port
PORT = 3000

# Change to the frontend directory
os.chdir(os.path.dirname(os.path.abspath(__file__)))

class MyHTTPRequestHandler(http.server.SimpleHTTPRequestHandler):
    def end_headers(self):
        # Add CORS headers
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type')
        super().end_headers()

    def do_OPTIONS(self):
        self.send_response(200)
        self.end_headers()

if __name__ == "__main__":
    Handler = MyHTTPRequestHandler
    
    with socketserver.TCPServer(("", PORT), Handler) as httpd:
        print(f"🚀 Frontend server running at http://localhost:{PORT}")
        print(f"📁 Serving files from: {Path.cwd()}")
        print(f"🔗 Backend API should be running at: http://localhost:8000")
        print("\n" + "="*50)
        print("📱 Open your browser and go to:")
        print(f"   http://localhost:{PORT}")
        print("="*50)
        print("\nPress Ctrl+C to stop the server")
        
        # Auto-open browser
        try:
            webbrowser.open(f'http://localhost:{PORT}')
        except:
            pass
        
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            print("\n\n🛑 Server stopped")
