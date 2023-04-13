import os
import tkinter as tk
from tkinter import ttk, filedialog
from tkinterdnd2 import DND_FILES, TkinterDnD

class MultiUpClient(TkinterDnD.Tk):
    def __init__(self):
        super().__init__()

        self.title('MultiUp Client')
        self.geometry('800x600')
        self.resizable(False, False)

        # Create widgets
        self.file_list = ttk.Treeview(self)
        self.server_list = ttk.Treeview(self)
        self.select_button = ttk.Button(self, text='Select File or Folder', command=self.select_file_or_folder)
        self.login_button = ttk.Button(self, text='Login', command=self.login)
        self.server_lookup_button = ttk.Button(self, text='Server Lookup', command=self.server_lookup)
        self.username_label = ttk.Label(self, text='Username:')
        self.username_entry = ttk.Entry(self)
        self.password_label = ttk.Label(self, text='Password:')
        self.password_entry = ttk.Entry(self, show='*')

        # Place widgets
        self.file_list.place(x=10, y=30, anchor='nw', width=630, height=450)
        self.server_list.place(x=645, y=30, anchor='nw', width=145, height=450)
        self.username_label.place(x=5, y=510)
        self.username_entry.place(x=70, y=510)
        self.password_label.place(x=5, y=535)
        self.password_entry.place(x=70, y=535)
        self.login_button.place(x=80, y=560)
        self.select_button.place(x=250, y=490)
        self.server_lookup_button.place(x=670, y=490)

        self.file_list.heading('#0', text='Files', anchor='center')
        self.server_list.heading('#0', text='Servers', anchor='center')

        # Drag and drop support
        self.file_list.drop_target_register(DND_FILES)
        self.file_list.dnd_bind('<<Drop>>', self.on_dnd_drop)

    def select_file_or_folder(self):
        file_opt = {
            'defaultextension': '',
            'filetypes': [('All files', '*.*')],
            'initialdir': os.path.expanduser('~'),
            'title': 'Select a file or folder',
        }

        file_name = filedialog.askopenfilename(**file_opt)
        if file_name:
            self.file_list.insert('', 'end', text=file_name)
        else:
            folder_name = filedialog.askdirectory(initialdir=os.path.expanduser('~'), title='Select a folder')
            if folder_name:
                self.file_list.insert('', 'end', text=folder_name)

    def login(self):
        pass

    def server_lookup(self):
        pass

    def on_dnd_drop(self, event):
        files = event.data.split()
        for file in files:
            self.file_list.insert('', 'end', text=file)

def main():
    app = MultiUpClient()
    app.mainloop()

if __name__ == "__main__":
    main()
