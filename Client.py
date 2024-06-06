import tkinter as tk  # For creating graphical user interfaces
from tkinter import filedialog, messagebox  # For file dialogs and message boxes
from tkinter import ttk  # For themed tkinter widgets
from PIL import Image, ImageTk, ImageSequence  # For handling images and animated GIFs
import socket  # For network communications
import ssl  # For secure socket layer
import threading  # For concurrent operations
import os  # For interacting with the operating system


class SecureSocket:
    @staticmethod
    def create_connection():
        """
        Create a secure SSL connection to the server.

        Returns:
            socket.socket: A secure client socket wrapped with SSL.
        """
        context = ssl.create_default_context()
        context.load_verify_locations("certificates/server.crt")
        client_socket = context.wrap_socket(socket.socket(socket.AF_INET), server_hostname="localhost")
        client_socket.connect(("localhost", 9999))
        return client_socket


class UserActions:
    @staticmethod
    def register_user(username, password):
        """
        Register a user with the provided username and password.

        Parameters:
            username (str): The username of the new user.
            password (str): The password of the new user.

        Returns: None
        """
        if not username or not password:
            messagebox.showwarning("Input Error", "Username and Password cannot be blank.")
            return
        client_socket = SecureSocket.create_connection()
        client_socket.send(f"REGISTER {username} {password}".encode())
        response = client_socket.recv(1024).decode()
        client_socket.close()
        messagebox.showinfo("Registration", response)

    @staticmethod
    def login_user(username, password):
        """
        Log in a user with the provided username and password.

        Parameters:
            username (str): The username of the user.
            password (str): The password of the user.

        Returns:
            bool: True if login is successful, otherwise False.
        """
        if not username or not password:
            messagebox.showwarning("Input Error", "Username and Password cannot be blank.")
            return False
        client_socket = SecureSocket.create_connection()
        client_socket.send(f"LOGIN {username} {password}".encode())
        response = client_socket.recv(1024).decode()
        client_socket.close()
        messagebox.showinfo("Login", response)
        return response == "Login successful!"

    @staticmethod
    def upload_file(username, app):
        """
        Upload a file for the given user.

        Parameters:
            username (str): The username of the user.
            app (Application): The instance of the Application class.

        Returns: None
        """
        file_path = filedialog.askopenfilename()
        if file_path:
            client_socket = SecureSocket.create_connection()
            filename = os.path.basename(file_path)

            def send_file():
                try:
                    client_socket.send(f"UPLOAD {username} {file_path}".encode())
                    response = client_socket.recv(1024).decode()
                except Exception as e:
                    response = f"Error: {str(e)}"
                finally:
                    client_socket.close()
                    app.stop_loading_animation()
                    messagebox.showinfo("File Upload", response)

            app.start_loading_animation()
            threading.Thread(target=send_file).start()


class Application(tk.Tk):
    def __init__(self):
        """
        Initialize the application window and its components.
        """
        super().__init__()
        self.title("CharlieScan")
        self.geometry("800x600")
        self.configure(bg='#2C3E50')
        self.iconbitmap("images/logo.ico")

        # Set up the canvas and background image
        self.canvas = tk.Canvas(self, width=800, height=600)
        self.canvas.pack(fill=tk.BOTH, expand=True)
        self.original_background_image = Image.open("images/background.jpg")
        self.background_image = self.original_background_image.resize((800, 600), Image.LANCZOS)
        self.background_photo = ImageTk.PhotoImage(self.background_image)
        self.canvas.create_image(0, 0, anchor=tk.NW, image=self.background_photo)
        self.canvas.lower("all")
        self.bind('<Configure>', self.update_background)

        # Configure styles for the widgets
        style = ttk.Style()
        style.theme_use('clam')
        style.configure("TLabel", font=("Helvetica", 14), background="#34495E", foreground="white")
        style.configure("TButton", font=("Helvetica", 12, "bold"), padding=10, background="#E74C3C", foreground="white")
        style.configure("TEntry", font=("Helvetica", 12))

        # Create and configure the main frame
        self.frame = ttk.Frame(self.canvas, padding="20 20 20 20", style="My.TFrame")
        self.frame.place(relx=0.5, rely=0.5, anchor=tk.CENTER)
        self.frame.grid_rowconfigure(0, weight=1)
        self.frame.grid_rowconfigure(1, weight=1)
        self.frame.grid_rowconfigure(2, weight=1)
        self.frame.grid_rowconfigure(3, weight=1)
        self.frame.grid_rowconfigure(4, weight=1)
        self.frame.grid_columnconfigure(0, weight=1)
        self.frame.grid_columnconfigure(1, weight=1)

        # Load and display the logo image
        self.logo_image = Image.open("images/logo.png")
        self.logo_image = self.logo_image.resize((100, 100), Image.LANCZOS)
        self.logo_photo = ImageTk.PhotoImage(self.logo_image)
        self.logo_label = tk.Label(self.frame, image=self.logo_photo, background="#2C3E50")
        self.logo_label.grid(row=0, column=0, columnspan=2, pady=10)

        # Add labels and entry fields for username and password
        ttk.Label(self.frame, text="Username").grid(row=1, column=0, padx=10, pady=10, sticky=tk.E)
        ttk.Label(self.frame, text="Password").grid(row=2, column=0, padx=10, pady=10, sticky=tk.E)

        self.username_entry = ttk.Entry(self.frame)
        self.password_entry = ttk.Entry(self.frame, show="*")
        self.username_entry.grid(row=1, column=1, padx=10, pady=10, sticky=tk.W)
        self.password_entry.grid(row=2, column=1, padx=10, pady=10, sticky=tk.W)

        # Add buttons for registration and login
        ttk.Button(self.frame, text="Register", command=lambda: UserActions.register_user(self.username_entry.get(),
                                                                                          self.password_entry.get())).grid(
            row=3, column=0, pady=10, padx=5, sticky=tk.EW)
        ttk.Button(self.frame, text="Login",
                   command=lambda: UserActions.login_user(self.username_entry.get(), self.password_entry.get())).grid(
            row=3,
            column=1,
            pady=10,
            padx=5,
            sticky=tk.EW)

        # Add an upload button that is initially disabled
        self.upload_button = ttk.Button(self.canvas, text="Upload File", state=tk.DISABLED)
        self.upload_button.place(relx=0.5, rely=0.9, anchor=tk.CENTER)
        self.upload_button.config(command=lambda: UserActions.upload_file(self.username_entry.get(), self))

        # Add a button for login and enabling the upload button
        ttk.Button(self.frame, text="Login & Enable Upload", command=self.enable_upload).grid(row=4, column=0,
                                                                                              columnspan=2, pady=10,
                                                                                              sticky=tk.EW)

        # Loading animation
        self.loading_label = tk.Label(self, background="#2C3E50")
        self.loading = False
        self.loading_frames = self.load_resized_gif("images/loading.gif", (320, 400))
        self.loading_frame_index = 0

    def load_resized_gif(self, gif_path, size):
        """
        Load and resize a GIF for the loading animation.

        Parameters:
            gif_path (str): The path to the GIF file.
            size (tuple): The size to resize the GIF frames to.

        Returns:
            list: A list of resized GIF frames.
        """
        gif = Image.open(gif_path)
        frames = [ImageTk.PhotoImage(img.resize(size, Image.LANCZOS)) for img in ImageSequence.Iterator(gif)]
        return frames

    def update_background(self, event=None):
        """
        Update the background image when the window is resized.

        Parameters:
            event (tk.Event): The event that triggered the update.

        Returns: None
        """
        new_width = self.canvas.winfo_width()
        new_height = self.canvas.winfo_height()
        self.background_image = self.original_background_image.resize((new_width, new_height), Image.LANCZOS)
        self.background_photo = ImageTk.PhotoImage(self.background_image)
        self.canvas.create_image(0, 0, anchor=tk.NW, image=self.background_photo)
        self.canvas.lower("all")

    def enable_upload(self):
        """
        Enable the upload button after successful login.

        Returns: None
        """
        if UserActions.login_user(self.username_entry.get(), self.password_entry.get()):
            self.upload_button.config(state=tk.NORMAL)
        else:
            self.upload_button.config(state=tk.DISABLED)

    def start_loading_animation(self):
        """
        Start the loading animation.

        Returns: None
        """
        self.loading = True
        self.loading_label.place(relx=0.5, rely=0.5, anchor=tk.CENTER)
        self.animate_loading()

    def stop_loading_animation(self):
        """
        Stop the loading animation.

        Returns: None
        """
        self.loading = False
        self.loading_label.place_forget()

    def animate_loading(self):
        """
        Animate the loading GIF.

        Returns: None
        """
        if self.loading:
            self.loading_label.config(image=self.loading_frames[self.loading_frame_index])
            self.loading_frame_index = (self.loading_frame_index + 1) % len(self.loading_frames)
            self.after(50, self.animate_loading)  # Adjusted to 50 ms for smoother animation


if __name__ == "__main__":
    # Create and start the application
    app = Application()
    app.mainloop()
