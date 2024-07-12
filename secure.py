import tkinter as tk
from cryptography.fernet import Fernet
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
from tkinter import filedialog
import os

class FileEncryptionApp:
    def __init__(self, master):
        self.master = master
        master.title("File Encryption/Decryption Utility")

        # Encryption method variable
        self.encryption_method = tk.StringVar(value="fernet")

        # Generate a random key for Fernet
        self.fernet_key = Fernet.generate_key()

        # Generate a random key for AES
        self.aes_key = get_random_bytes(16)  # For AES, a 128-bit key

        # Input fields
        self.input_label = tk.Label(master, text="Input File:")
        self.input_label.pack()

        self.input_file_entry = tk.Entry(master)
        self.input_file_entry.pack()

        self.input_browse_button = tk.Button(master, text="Browse", command=self.browse_file)
        self.input_browse_button.pack()

        # Output fields
        self.output_label = tk.Label(master, text="Output Directory:")
        self.output_label.pack()

        self.output_file_entry = tk.Entry(master)
        self.output_file_entry.pack()

        self.output_browse_button = tk.Button(master, text="Browse", command=self.browse_output_directory)
        self.output_browse_button.pack()

        # Radio buttons for encryption method
        self.fernet_radio = tk.Radiobutton(master, text="Fernet", variable=self.encryption_method, value="fernet")
        self.fernet_radio.pack()

        self.aes_radio = tk.Radiobutton(master, text="AES", variable=self.encryption_method, value="aes")
        self.aes_radio.pack()

        # Buttons
        self.encrypt_button = tk.Button(master, text="Encrypt", command=self.encrypt_file)
        self.encrypt_button.pack()

        self.decrypt_button = tk.Button(master, text="Decrypt", command=self.decrypt_file)
        self.decrypt_button.pack()

        # Result label
        self.result_label = tk.Label(master, text="")
        self.result_label.pack()

    def browse_file(self):
        file_path = filedialog.askopenfilename()
        self.input_file_entry.delete(0, tk.END)
        self.input_file_entry.insert(0, file_path)

    def browse_output_directory(self):
        directory_path = filedialog.askdirectory()
        self.output_file_entry.delete(0, tk.END)
        self.output_file_entry.insert(0, directory_path)

    def encrypt_file(self):
        input_file = self.input_file_entry.get()
        output_directory = self.output_file_entry.get()

        with open(input_file, 'rb') as f:
            data = f.read()

        if self.encryption_method.get() == "fernet":
            cipher_suite = Fernet(self.fernet_key)
            encrypted_data = cipher_suite.encrypt(data)
        else:  # AES
            cipher = AES.new(self.aes_key, AES.MODE_CBC)
            encrypted_data = cipher.encrypt(pad(data, AES.block_size))

        # Create an output file path
        input_filename = os.path.basename(input_file)
        output_file = os.path.join(output_directory, input_filename + ".encrypted")

        with open(output_file, 'wb') as f:
            f.write(encrypted_data)

        result_text = f'File "{input_filename}" encrypted and saved as "{output_file}"'
        self.result_label.config(text=result_text)

    def decrypt_file(self):
        input_file = self.input_file_entry.get()
        output_directory = self.output_file_entry.get()

        with open(input_file, 'rb') as f:
            data = f.read()

        if self.encryption_method.get() == "fernet":
            cipher_suite = Fernet(self.fernet_key)
            decrypted_data = cipher_suite.decrypt(data)
        else:  # AES
            cipher = AES.new(self.aes_key, AES.MODE_CBC)
            decrypted_data = unpad(cipher.decrypt(data), AES.block_size)

        # Create an output file path
        input_filename = os.path.basename(input_file)
        output_file = os.path.join(output_directory, input_filename.replace(".encrypted", ""))

        with open(output_file, 'wb') as f:
            f.write(decrypted_data)

        result_text = f'File "{input_filename}" decrypted and saved as "{output_file}"'
        self.result_label.config(text=result_text)

if __name__ == "__main__":
    root = tk.Tk()
    app = FileEncryptionApp(root)
    root.mainloop()
