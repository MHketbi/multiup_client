import os
import requests
import tkinter as tk
import tkinter.ttk as ttk
from tkinter import filedialog
from tkinterdnd2 import *
import json
import base64
from cryptography.fernet import Fernet
import getpass

def get_account_id(username, password):
    url = "https://multiup.org/api/get-user-id"
    data = {"user": username, "pass": password}
    response = requests.post(url, data=data)
    if response.status_code == 200:
        return response.json()["account_id"]
    else:
        return None

def upload_file(account_id, file_path):
    url = "https://multiup.org/api/upload"
    data = {"account_id": account_id}
    with open(file_path, "rb") as file:
        response = requests.post(url, data=data, files={"file": file})
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
    encrypted_username, username_key = encrypt_data(username)
    encrypted_password, password_key = encrypt_data(password)
    credentials = {
        "username": encrypted_username.decode(),
        "password": encrypted_password.decode(),
        "username_key": username_key.decode(),
        "password_key": password_key.decode()
    }
    with open("credentials.json", "w") as f:
        json.dump(credentials, f)

def load_credentials():
    try:
        with open("credentials.json", "r") as f:
            credentials = json.load(f)
        decrypted_username = decrypt_data(base64.b64decode(credentials["username"]),
                                          base64.b64decode(credentials["username_key"]))
        decrypted_password = decrypt_data(base64.b64decode(credentials["password"]),
                                          base64.b64decode(credentials["password_key"]))
        return decrypted_username, decrypted_password
    except FileNotFoundError:
        return None, None

class MultiUpClient(TkinterDnD.Tk):
    def __init__(self):
        super().__init__()

        self.title("MultiUp Client")
        self.geometry("800x500")
        self.resizable(False, False)

        self.create_widgets()

        username, password = load_credentials()
        if username and password:
            self.account_id = get_account_id(username, password)
            if self.account_id is not None:
                self.show_main_ui()
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

        self.select_button = ttk.Button(self, text="Select Files", command=self.select_files)
        self.select_button.place(x=20, y=450)

        self.logout_button = ttk.Button(self, text="Logout", command=self.logout)
        self.logout_button.place(x=480, y=450)

        self.upload_button = ttk.Button(self, text="Upload", command=self.upload_files)
        self.upload_button.place(x=350, y=350)

        self.login_button = ttk.Button(self, text="LOGIN", command=self.login_ui)
        self.login_button.place(x=375, y=250)

        self.username_label = ttk.Label(self, text="Username:")
        self.username_label.place(x=220, y=20)

        self.username_entry = ttk.Entry(self)
        self.username_entry.place(x=280, y=20)

        self.password_label = ttk.Label(self, text="Password:")
        self.password_label.place(x=220, y=60)

        self.password_entry = ttk.Entry(self, show="*")
        self.password_entry.place(x=280, y=60)

        self.submit_login_button = ttk.Button(self, text="Login", command=self.login)
        self.submit_login_button.place(x=350, y=100)

    def show_login_ui(self):
        self.file_list.place_forget()
        self.server_list.place_forget()
        self.select_button.place_forget()
        self.logout_button.place_forget()
        self.upload_button.place_forget()

        self.login_button.place(x=375, y=250)

    def login_ui(self):
        self.login_button.place_forget()

        self.username_label.place(x=220, y=20)
        self.username_entry.place(x=280, y=20)
        self.password_label.place(x=220, y=60)
        self.password_entry.place(x=280, y=60)
        self.submit_login_button.place(x=350, y=100)

    def login(self):
        username = self.username_entry.get()
        password = self.password_entry.get()

        self.account_id = get_account_id(username, password)
        if self.account_id is not None:
            save_credentials(username, password)
            self.show_main_ui()
        else:
            print("Invalid credentials")

    def show_main_ui(self):
        self.username_label.place_forget()
        self.username_entry.place_forget()
        self.password_label.place_forget()
        self.password_entry.place_forget()
        self.submit_login_button.place_forget()

        self.file_list.place(x=20, y=20, width=300, height=400)
        self.server_list.place(x=480, y=20, width=300, height=400)
        self.select_button.place(x=20, y=450)
        self.logout_button.place(x=480, y=450)
        self.upload_button.place(x=350, y=350)

    def logout(self):
        try:
            os.remove("credentials.json")
        except FileNotFoundError:
            pass
        self.account_id = None
        self.show_login_ui()

    def select_files(self):
        file_paths = filedialog.askopenfilenames()
        for file_path in file_paths:
            self.file_list.insert("", "end", text=os.path.basename(file_path), values=(file_path,))

    def upload_files(self):
        if self.account_id is not None:
            selected_files = self.file_list.selection()
            for file_item in selected_files:
                file_path = self.file_list.item(file_item)["values"][0]
                print(f"Uploading {file_path}")
                response = upload_file(self.account_id, file_path)
                print(response)
        else:
            print("Please log in first")

if __name__ == "__main__":
    app = MultiUpClient()
    app.mainloop()

