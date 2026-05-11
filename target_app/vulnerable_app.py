#!/usr/bin/env python3
"""
Vulnerable Web Application for CTI Pipeline Testing
This app contains intentional vulnerabilities for testing the security pipeline.
"""

from flask import Flask, request, render_template_string
import sqlite3
import subprocess
import os

app = Flask(__name__)

# Vulnerable database setup
def setup_db():
    """Create a vulnerable database."""
    conn = sqlite3.connect('vulnerable.db')
    cursor = conn.cursor()
    
    # Create users table with SQL injection vulnerability
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY,
            username TEXT,
            password TEXT,
            role TEXT
        )
    ''')
    
    # Insert some test data
    cursor.execute("INSERT INTO users (username, password, role) VALUES (?, ?, ?)", 
                 ("admin", "password123", "admin"))
    cursor.execute("INSERT INTO users (username, password, role) VALUES (?, ?, ?)", 
                 ("user1", "userpass", "user"))
    
    conn.commit()
    conn.close()

# Vulnerable login route with SQL injection
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username', '')
        password = request.form.get('password', '')
        
        # SQL Injection vulnerability - direct string concatenation
        conn = sqlite3.connect('vulnerable.db')
        cursor = conn.cursor()
        
        query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
        print(f"[DEBUG] Query: {query}")
        
        try:
            cursor.execute(query)
            user = cursor.fetchone()
            conn.close()
            
            if user:
                return f"Welcome {user[1]}! Role: {user[2]}"
            else:
                return "Login failed!"
        except Exception as e:
            return f"Database error: {e}"
    
    # Login form with XSS vulnerability
    return '''
    <!DOCTYPE html>
    <html>
    <head><title>Vulnerable Login</title></head>
    <body>
        <h2>Login (Vulnerable)</h2>
        <form method="post">
            Username: <input type="text" name="username"><br>
            Password: <input type="password" name="password"><br>
            <input type="submit" value="Login">
        </form>
        <p>Vulnerabilities: SQL Injection, XSS</p>
    </body>
    </html>
    '''

# Vulnerable search with XSS
@app.route('/search')
def search():
    query = request.args.get('q', '')
    
    # XSS vulnerability - direct output without sanitization
    return f'''
    <!DOCTYPE html>
    <html>
    <head><title>Search Results</title></head>
    <body>
        <h2>Search Results for: {query}</h2>
        <p>Vulnerability: Reflected XSS</p>
        <a href="/login">Back to Login</a>
    </body>
    </html>
    '''

# Command injection vulnerability
@app.route('/ping')
def ping():
    host = request.args.get('host', '127.0.0.1')
    
    # Command injection vulnerability
    try:
        result = subprocess.run(f'ping -c 4 {host}', shell=True, 
                              capture_output=True, text=True)
        return f"Ping results: {result.stdout}"
    except Exception as e:
        return f"Error: {e}"

# Path traversal vulnerability
@app.route('/file')
def file_view():
    filename = request.args.get('file', 'readme.txt')
    
    # Path traversal vulnerability
    try:
        with open(filename, 'r') as f:
            content = f.read()
        return f"File content: {content}"
    except Exception as e:
        return f"Error reading file: {e}"

# Insecure deserialization
@app.route('/api/data')
def api_data():
    import pickle
    import base64
    
    data = request.args.get('data', '')
    
    if data:
        try:
            # Insecure deserialization
            decoded = base64.b64decode(data)
            obj = pickle.loads(decoded)
            return f"Deserialized: {obj}"
        except Exception as e:
            return f"Deserialization error: {e}"
    
    return "No data provided"

# Information disclosure
@app.route('/debug')
def debug():
    # Debug information disclosure
    return f'''
    <!DOCTYPE html>
    <html>
    <head><title>Debug Info</title></head>
    <body>
        <h2>Debug Information</h2>
        <p>Server: {request.host}</p>
        <p>User Agent: {request.headers.get('User-Agent', 'Unknown')}</p>
        <p>Environment: {os.environ.get('ENVIRONMENT', 'development')}</p>
        <p>Vulnerability: Information Disclosure</p>
    </body>
    </html>
    '''

# Main page with vulnerability list
@app.route('/')
def index():
    return '''
    <!DOCTYPE html>
    <html>
    <head>
        <title>CTI Test Application</title>
        <style>
            body { font-family: Arial, sans-serif; margin: 40px; }
            .vuln { background: #ffe6e6; padding: 10px; margin: 10px 0; border-left: 4px solid #ff4444; }
            .safe { background: #e6ffe6; padding: 10px; margin: 10px 0; border-left: 4px solid #44ff44; }
        </style>
    </head>
    <body>
        <h1>🔒 CTI Pipeline Test Application</h1>
        <p>This application contains intentional vulnerabilities for testing the security pipeline.</p>
        
        <div class="vuln">
            <h3>🚨 Vulnerable Endpoints:</h3>
            <ul>
                <li><a href="/login">/login</a> - SQL Injection & XSS</li>
                <li><a href="/search?q=test">/search</a> - Reflected XSS</li>
                <li><a href="/ping?host=127.0.0.1">/ping</a> - Command Injection</li>
                <li><a href="/file?file=readme.txt">/file</a> - Path Traversal</li>
                <li><a href="/api/data?data=...">/api/data</a> - Insecure Deserialization</li>
                <li><a href="/debug">/debug</a> - Information Disclosure</li>
            </ul>
        </div>
        
        <div class="safe">
            <h3>✅ Safe Features:</h3>
            <ul>
                <li>Static content serving</li>
                <li>Basic error handling</li>
                <li>Development mode logging</li>
            </ul>
        </div>
        
        <h3>📋 Expected CVEs from Scan:</h3>
        <ul>
            <li>CVE-2023-1234 (SQL Injection)</li>
            <li>CVE-2023-1235 (XSS)</li>
            <li>CVE-2023-1236 (Command Injection)</li>
            <li>CVE-2023-1237 (Path Traversal)</li>
            <li>CVE-2023-1238 (Insecure Deserialization)</li>
        </ul>
    </body>
    </html>
    '''

if __name__ == '__main__':
    setup_db()
    app.run(debug=True, host='0.0.0.0', port=5000)
