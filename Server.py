import socket  # For network communications
import threading  # For concurrent operations
import sqlite3  # For database management
import ssl  # For secure socket layer to provide secure communication over the network
import bcrypt  # For password hashing to securely store passwords
from pe_analyzer import PEAnalyzer  # Import the PEAnalyzer class for file analysis to detect malware
import time  # For tracking connection times and rate limiting
from collections import defaultdict  # For managing connections and their counts efficiently


class DatabaseManager:
    def __init__(self, db_name='users.db'):
        """
        Initialize the DatabaseManager with a specified database name.

        Parameters:
            db_name (str): The name of the SQLite database file. Defaults to 'users.db'.
        """
        self.db_name = db_name
        self.initialize_db()

    def initialize_db(self):
        """
        Initialize the database by creating the users table if it doesn't exist.

        This method establishes a connection to the SQLite database, creates a 'users' table
        with 'username' and 'password' columns, and then closes the connection.
        """
        conn = sqlite3.connect(self.db_name)
        cursor = conn.cursor()
        cursor.execute('''CREATE TABLE IF NOT EXISTS users (username TEXT PRIMARY KEY, password TEXT)''')
        conn.commit()
        conn.close()

    def register_user(self, username, password):
        """
        Register a new user in the database.

        Parameters:
            username (str): The username of the new user.
            password (str): The password of the new user.

        Returns:
            str: A message indicating whether the registration was successful or if the username already exists.
        """
        conn = sqlite3.connect(self.db_name)
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
        if cursor.fetchone():
            conn.close()
            return "Username already exists!"

        hashed_password = bcrypt.hashpw(password.encode(), bcrypt.gensalt())
        cursor.execute("INSERT INTO users (username, password) VALUES (?, ?)", (username, hashed_password))
        conn.commit()
        conn.close()
        return "Registration successful!"

    def validate_user(self, username, password):
        """
        Validate a user's login credentials.

        Parameters:
            username (str): The username of the user.
            password (str): The password of the user.

        Returns:
            bool: True if the credentials are valid, otherwise False.
        """
        conn = sqlite3.connect(self.db_name)
        cursor = conn.cursor()
        cursor.execute("SELECT password FROM users WHERE username = ?", (username,))
        result = cursor.fetchone()
        conn.close()
        if result and bcrypt.checkpw(password.encode(), result[0]):
            return True
        return False


class ClientHandler(threading.Thread):
    def __init__(self, client_socket, db, analyzer):
        """
        Initialize a ClientHandler thread to handle client requests.

        Parameters:
            client_socket (socket.socket): The client socket for communication.
            db (DatabaseManager): An instance of the DatabaseManager for user authentication.
            analyzer (PEAnalyzer): An instance of the PEAnalyzer for file analysis.
        """
        threading.Thread.__init__(self)
        self.client_socket = client_socket
        self.db = db
        self.analyzer = analyzer

    def run(self):
        """
        Handle client requests in a separate thread.

        This method processes different types of client requests such as REGISTER, LOGIN, and UPLOAD.
        It sends appropriate responses back to the client based on the request.
        """
        try:
            data = self.client_socket.recv(4096).decode()
            if data.startswith("REGISTER"):
                _, username, password = data.split()
                response = self.db.register_user(username, password)
                self.client_socket.send(response.encode())

            elif data.startswith("LOGIN"):
                _, username, password = data.split()
                if self.db.validate_user(username, password):
                    self.client_socket.send("Login successful!".encode())
                else:
                    self.client_socket.send("Login failed!".encode())

            elif data.startswith("UPLOAD"):
                parts = data.split()
                username = parts[1]
                file_path = parts[2]

                try:
                    with open(file_path, "rb") as file:
                        file_data = file.read()
                    analysis_result = self.analyzer.analyze_file(file_data)
                    self.client_socket.send(analysis_result.encode())
                except FileNotFoundError:
                    self.client_socket.send("Error: File not found.".encode())
                except Exception as e:
                    self.client_socket.send(f"Error: {str(e)}".encode())

        except Exception as e:
            self.client_socket.send(f"Error: {str(e)}".encode())
        finally:
            self.client_socket.close()





class Server:
    def __init__(self, host='0.0.0.0', port=9999, max_connections_per_minute=10):
        """
        Initialize the Server with specified host, port, and connection rate limit.

        Parameters:
            host (str): The server's host address. Defaults to '0.0.0.0' (all available interfaces).
            port (int): The server's port number. Defaults to 9999.
            max_connections_per_minute (int): Maximum allowed connections per minute from a single IP address.
        """
        self.host = host
        self.port = port
        self.db = DatabaseManager("users.db")
        self.analyzer = PEAnalyzer("data/PE Malware Detection Model.pkl", "data/yara_rules_dir")
        self.max_connections_per_minute = max_connections_per_minute
        self.connections = defaultdict(lambda: (0, time.time()))

    def start_server(self):
        """
        Start the server and handle incoming client connections.

        This method sets up an SSL context for secure communications, binds the server to the specified host and port,
        and listens for incoming connections. It handles rate limiting for incoming connections based on IP address.
        """
        context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        context.load_cert_chain(certfile="certificates/server.crt", keyfile="certificates/server.key")

        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.bind((self.host, self.port))
        server_socket.listen(5)

        with context.wrap_socket(server_socket, server_side=True) as ssock:
            print(f"Server listening on {self.host}:{self.port}")
            while True:
                client_socket, addr = ssock.accept()
                if self.is_rate_limited(addr[0]):
                    print(f"Connection from {addr} denied: Rate limit exceeded")
                    client_socket.close()
                    continue
                print(f"Connection from {addr}")
                handler = ClientHandler(client_socket, self.db, self.analyzer)
                handler.start()

    def is_rate_limited(self, ip):
        """
        Check if a client IP address is rate limited.

        Parameters:
            ip (str): The IP address of the client.

        Returns:
            bool: True if the IP address exceeds the connection limit, otherwise False.
        """
        current_time = time.time()
        connection_count, start_time = self.connections[ip]
        if current_time - start_time > 60:
            self.connections[ip] = (1, current_time)
            return False
        elif connection_count < self.max_connections_per_minute:
            self.connections[ip] = (connection_count + 1, start_time)
            return False
        else:
            return True


if __name__ == "__main__":
    # Create and start the server
    server = Server()
    server.start_server()
