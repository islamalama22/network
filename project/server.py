import http.server
import socketserver
import base64
import time
import threading
from http.client import HTTPConnection
from urllib.parse import urlparse

PORT = 8000
SESSION_EXPIRY_SECONDS = 3600  # Session cookie expiry time in seconds (1 hour)

class MyHandler(http.server.BaseHTTPRequestHandler):
    AUTHORIZED_USERS = {"islam": "password"}
    session_data = {}
    session_cookie_name = "session_id"

    def do_AUTH_HEAD(self):
        self.send_response(401)
        self.send_header('WWW-Authenticate', 'Basic realm="Protected Area"')
        self.send_header('Content-type', 'text/html')
        self.end_headers()
        self.wfile.write(b"<h1>Authorization Required</h1>")

    def do_GET(self):
        if self.path == "/":
            # Serve the index.html page
            self.send_response(200)
            self.send_header("Content-type", "text/html")
            self.end_headers()
            with open("index.html", "rb") as f:
                content = f.read()
                self.wfile.write(content)
        elif 'Authorization' not in self.headers:
            self.do_AUTH_HEAD
            return
        else:
            print("Received Authorization header:", self.headers['Authorization'])

    def do_POST(self):
        if self.path == "/login":

            content_length = int(self.headers['Content-Length'])
            post_data = self.rfile.read(content_length).decode()
            username = self.parse_username(post_data)
            password = self.parse_password(post_data)

            if username is None or password is None:
                self.send_error(400, "Invalid username or password")
                return

            if username in self.AUTHORIZED_USERS and self.AUTHORIZED_USERS[username] == password:
                session_id = self.get_or_create_session(username)
                if self.session_cookie_name not in self.headers.get_all('Cookie'):
                    cookie_value = f"{self.session_cookie_name}={session_id}"
                    headers = {"Set-Cookie": cookie_value + f"; Max-Age={SESSION_EXPIRY_SECONDS}; Path=/; HttpOnly",
                               "Cache-Control": "max-age=3600"}
                    self.send_response(302)
                    self.send_header('Location', '/protected')
                    for key, value in headers.items():
                        self.send_header(key, value)
                    self.end_headers()
                else:
                    # User already has a valid cookie, redirect without setting a new one
                    self.send_response(302)
                    self.send_header('Location', '/protected')
                    self.end_headers()
            else:
                self.send_error(401, "Invalid Username or Password")
        else:
            self.send_error(404, "Not Found")

    def handle_authorized_request(self, username):
        # Check for session cookie
        session_id = None
        if self.session_cookie_name in self.headers.get_all('Cookie'):
            for cookie in self.headers.get_all('Cookie'):
                if cookie.split('=')[0] == self.session_cookie_name:
                    session_id = cookie.split('=')[1]
                    break

        # Validate session ID if cookie is found
        if session_id and session_id in self.session_data and self.session_data[session_id] == username:
            # Session valid, proceed
            cookie_value = f"{self.session_cookie_name}={session_id}"
            headers = {"Set-Cookie": cookie_value + f"; Max-Age={SESSION_EXPIRY_SECONDS}; Path=/; HttpOnly",
                    "Cache-Control": "max-age=3600"}

            if self.path == "/protected":
                self.send_response(200)
                self.send_header("Content-type", "text/html")
                for key, value in headers.items():
                    self.send_header(key, value)
                self.end_headers()

                with open("secand.html", "rb") as f:
                    content = f.read().decode()
                    content = content.replace("{username}", username)
                    response_status = 200
                    self.wfile.write(content.encode())
            elif self.path == "/index.html":
                self.send_static_content(username)
            else:
                self.send_error(404, "Not Found")
        else:
            # Session invalid, redirect to login
            self.send_response(302)
            self.send_header('Location', '/login')
            self.end_headers()

    def parse_username(self, post_data):
        try:
            username = post_data.split('username=')[1].split('&')[0]
            return username
        except:
            return None

    def parse_password(self, post_data):
        try:
            password = post_data.split('password=')[1].split('&')[0]
            return password
        except:
            return None

    def get_or_create_session(self, username):
        if username in self.session_data:
            return self.session_data[username]
        else:
            session_id = f"{username}-{int(time.time())}"
            self.session_data[session_id] = username
            return session_id
        
def start_server():
    """
    Starts the HTTP server.
    """
    global httpd
    handler = MyHandler
    with socketserver.ThreadingTCPServer(("", PORT), handler) as httpd:
        print('http://localhost:8000')
        httpd.serve_forever()

if __name__ == "__main__":
    main_thread = threading.Thread(target=start_server)
    main_thread.start()
