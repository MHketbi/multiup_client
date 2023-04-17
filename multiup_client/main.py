import os
from tkinter import filedialog
import tkinter as tk
import tkinter.ttk as ttk
from tkinterdnd2 import *
import json
import base64
from cryptography.fernet import Fernet
import requests
import keyring

def login(username, password):
    url = "https://multiup.org/api/login"
    data = {"username": username, "password": password}
    response = requests.post(url, data=data)
    if response.status_code == 200:
        return response.json()
    else:
        return None

def get_fastest_server():
    url = "https://multiup.org/api/get-fastest-server"
    response = requests.get(url)
    if response.status_code == 200:
        return response.json()["server"]
    else:
        return None

def get_list_hosts():
    url = "https://multiup.org/api/get-list-hosts"
    response = requests.get(url)
    if response.status_code == 200:
        return response.json()["hosts"]
    else:
        return None

def upload_file(user, server, file_path):
    url = f"https://{server}.multiup.org/upload/index.php"
    with open(file_path, "rb") as file:
        files = {"files[]": file}
        data = {"user": user}
        response = requests.post(url, data=data, files=files)
    if response.status_code == 200:
        return response.json()
    else:
        return None

def encrypt_data(data):
    key = Fernet.generate_key()
    cipher_suite = Fernet(key)
    encrypted_data = cipher_suite.encrypt(data.encode())
    return encrypted_data, key

def decrypt_data(encrypted_data, key):
    cipher_suite = Fernet(key)
    decrypted_data = cipher_suite.decrypt(encrypted_data)
    return decrypted_data.decode()

def save_credentials(username, password):
    try:
        keyring.set_password("multiup_client", "username", username)
        keyring.set_password("multiup_client", "password", password)
        print("Credentials saved successfully")
    except Exception as e:
        print("Error saving credentials:", e)

def load_credentials():
    try:
        username = keyring.get_password("multiup_client", "username")
        password = keyring.get_password("multiup_client", "password")
        return username, password
    except Exception as e:
        print("Error loading credentials:", e)
        return None, None

def save_login_state(logged_in):
    with open("login_state.json", "w") as f:
        json.dump({"logged_in": logged_in}, f)

def load_login_state():
    try:
        with open("login_state.json", "r") as f:
            state = json.load(f)
        return state["logged_in"]
    except FileNotFoundError:
        return False

def get_account_id(username, password):
    login_response = login(username, password)
    if login_response and login_response["error"] == "success":
        return login_response["user"]
    else:
        return None

def get_list_hosts():
    url = "https://multiup.org/api/get-list-hosts"
    response = requests.get(url)
    if response.status_code == 200:
        return response.json()["hosts"]
    else:
        return None

class MultiUpClient(TkinterDnD.Tk):
    def __init__(self):
        super().__init__()

        self.protocol("WM_DELETE_WINDOW", self.on_close)

        self.title("MultiUp Client")
        self.resizable(False, False)

        self.create_widgets()

        self.logged_in = load_login_state()
        if self.logged_in:
            username, password = load_credentials()
            if username and password:
                self.account_id = get_account_id(username, password)
                if self.account_id is not None:
                    self.show_main_ui()
                else:
                    self.show_login_ui()
            else:
                self.show_login_ui()
        else:
            self.show_login_ui()

    def create_widgets(self):
        self.file_list = ttk.Treeview(self, columns=("Files",), show="headings")
        self.file_list.heading("Files", text="Files")
        self.file_list.place(x=20, y=20, width=300, height=400)

        self.server_list = ttk.Treeview(self, columns=("Servers",), show="headings")
        self.server_list.heading("Servers", text="Servers")
        self.server_list.place(x=480, y=20, width=300, height=400)

        self.select_server_button = ttk.Button(self, text="Select Server", command=self.select_server)
        self.select_server_button.place(x=360, y=140)

        self.select_button = ttk.Button(self, text="Select Files", command=self.select_files)
        self.select_button.place(x=360, y=180)

        self.upload_button = ttk.Button(self, text="Upload", command=self.upload_files)
        self.upload_button.place(x=360, y=220)

        self.logout_button = ttk.Button(self, text="Logout", command=self.logout)
        self.logout_button.place(x=360, y=260)

        self.username_label = ttk.Label(self, text="Username:")
        self.username_label.place(x=50, y=20)

        self.username_entry = ttk.Entry(self)
        self.username_entry.place(x=110, y=20)

        self.password_label = ttk.Label(self, text="Password:")
        self.password_label.place(x=50, y=60)

        self.password_entry = ttk.Entry(self, show="*")
        self.password_entry.place(x=110, y=60)

        self.submit_login_button = ttk.Button(self, text="Login", command=self.login)
        self.submit_login_button.place(x=150, y=100)

        self.error_label = ttk.Label(self, text="", foreground="red")
        self.error_label.place(x=120, y=20)

    def show_login_ui(self):
        self.geometry("400x200")
        self.file_list.place_forget()
        self.server_list.place_forget()
        self.select_server_button.place_forget()
        self.select_button.place_forget()
        self.logout_button.place_forget()
        self.upload_button.place_forget()

        self.username_label.place(x=100, y=50)
        self.username_entry.place(x=160, y=50)
        self.password_label.place(x=100, y=90)
        self.password_entry.place(x=160, y=90)
        self.submit_login_button.place(x=170, y=130)

    def login(self):
        username = self.username_entry.get()
        password = self.password_entry.get()

        if not username and not password:
            self.error_label.config(text="Please type in user credentials")
        elif not username:
            self.error_label.config(text="Please type in username")
        elif not password:
            self.error_label.config(text="Please type in password")
        else:
            login_response = login(username, password)
            if login_response and login_response["error"] == "success":
                save_credentials(username, password)
                self.user_info = {
                    "user": login_response["user"],
                    "account_type": login_response["account_type"],
                    "premium_days_left": login_response["premium_days_left"],
                }
                self.show_main_ui()
            else:
                self.error_label.config(text="Invalid credentials")

    def show_main_ui(self):
        self.geometry("800x500")
        self.username_label.place_forget()
        self.username_entry.place_forget()
        self.password_label.place_forget()
        self.password_entry.place_forget()
        self.submit_login_button.place_forget()

        self.file_list.place(x=20, y=20, width=300, height=400)
        self.server_list.place(x=480, y=20, width=300, height=400)
        self.select_server_button.place(x=360, y=140)
        self.select_button.place(x=360, y=180)
        self.upload_button.place(x=360, y=220)
        self.logout_button.place(x=360, y=260)

    def logout(self):
        try:
            os.remove("credentials.json")
        except FileNotFoundError:
            pass
        save_login_state(False)
        self.user_info = None
        self.show_login_ui()

    def select_files(self):
        file_paths = filedialog.askopenfilenames()
        for file_path in file_paths:
            self.file_list.insert("", "end", text=os.path.basename(file_path), values=(file_path,))

    def select_files(self):
        file_paths = filedialog.askopenfilenames()
        for file_path in file_paths:
            self.file_list.insert("", "end", text=os.path.basename(file_path), values=(file_path,))

    def select_server(self):
        hosts = get_list_hosts()
        if hosts is not None:
            self.server_list.delete(*self.server_list.get_children())
            for host in hosts:
                self.server_list.insert("", "end", text=host, values=(host,))
        else:
            print("Failed to get the list of available hosts")

    def upload_files(self):
        if self.user_info is not None:
            selected_files = self.file_list.selection()
            server = get_fastest_server()
            if server is None:
                print("Failed to get the fastest server")
                return
            for file_item in selected_files:
                file_path = self.file_list.item(file_item)["values"][0]
                print(f"Uploading {file_path}")
                response = upload_file(self.user_info["user"], server, file_path)
                print(response)
        else:
            print("Please log in first")

    def on_close(self):
        if self.user_info is not None:
            save_login_state(True)
        else:
            save_login_state(False)
        self.destroy()

if __name__ == "__main__":
    app = MultiUpClient()
    app.mainloop()
