import tkinter as tk
from tkinter import filedialog
import subprocess
import os
import sys
from secure import FileEncryptionApp
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

class CustomCLI:
    def _init_(self, master): #initializing the CLI interface
        self.master = master
        master.title("Custom CLI Simulation")

        # Current directory
        self.current_directory = os.getcwd()

        # History text
        self.history_text = tk.Text(master, height=10, width=80)
        self.history_text.pack(side=tk.TOP, padx=10, pady=10)
        self.history_text.insert(tk.END, f"Current Directory: {self.current_directory}\n\n")

        # Input frame
        input_frame = tk.Frame(master)
        input_frame.pack(side=tk.BOTTOM, padx=10, pady=10)

        # Command Label
        self.command_label = tk.Label(input_frame, text="Command:")
        self.command_label.pack(side=tk.LEFT)

        # Command Entry
        self.command_entry = tk.Entry(input_frame, width=50)
        self.command_entry.pack(side=tk.LEFT, padx=5)

        # Execute Button
        self.execute_button = tk.Button(input_frame, text="Execute", command=self.execute_command)
        self.execute_button.pack(side=tk.LEFT, padx=5)

        # Clear Screen Button
        self.clear_screen_button = tk.Button(input_frame, text="Clear Screen", command=self.clear_screen)
        self.clear_screen_button.pack(side=tk.LEFT, padx=5)

        # Bindings
        self.master.bind('<Return>', lambda event=None: self.execute_command())
        self.master.bind('<Up>', self.navigate_command_history)
        self.master.bind('<Down>', self.navigate_command_history)
    
    def encrypt_file(self, file_path):
        try:
            # Generate a Fernet key and save it to a file
            key = Fernet.generate_key()
            with open('encryption_key.key', 'wb') as key_file:
                key_file.write(key)

            # Read the file content
            with open(file_path, 'rb') as file:
                file_data = file.read()

            # Create a Fernet cipher suite and encrypt the file content
            cipher_suite = Fernet(key)
            encrypted_data = cipher_suite.encrypt(file_data)

            # Save the encrypted content to the same file
            with open(file_path, 'wb') as file:
                file.write(encrypted_data)

            self.history_text.insert(tk.END, f"Encrypted file: {file_path}\n")
        except Exception as e:
            self.history_text.insert(tk.END, f"Error encrypting file: {str(e)}\n")
        self.history_text.see(tk.END)

    def decrypt_file(self, file_path):
        try:
            # Read the Fernet key from the key file
            with open('encryption_key.key', 'rb') as key_file:
                key = key_file.read()

            # Read the encrypted file content
            with open(file_path, 'rb') as file:
                encrypted_data = file.read()

            # Create a Fernet cipher suite and decrypt the file content
            cipher_suite = Fernet(key)
            decrypted_data = cipher_suite.decrypt(encrypted_data)

            # Save the decrypted content to the same file
            with open(file_path, 'wb') as file:
                file.write(decrypted_data)

            self.history_text.insert(tk.END, f"Decrypted file: {file_path}\n")
        except Exception as e:
            self.history_text.insert(tk.END, f"Error decrypting file: {str(e)}\n")
        self.history_text.see(tk.END)
    def execute_command(self): # Adding executed command in history, and function calls for execution
        command = self.command_entry.get().lower()

        # Add the executed command to the history
        self.history_text.insert(tk.END, f"Command: {command}\n")
        self.history_text.see(tk.END)

        if command == "clear":
            self.clear_screen()
        elif command.startswith("open "):
            path_to_open = command.split(" ")[1]
            self.open_folder_or_file(path_to_open)
        elif command == "listdirectory":
            self.list_directory()
        elif command.startswith("delete "):
            file_or_folder = command.split(" ")[1]
            self.delete_file_or_folder(file_or_folder)
        elif command.startswith("create "):
            file_or_folder = command.split(" ")[1]
            self.create_file_or_folder(file_or_folder)
        elif command.startswith("move "):
            paths = command.split(" ")[1:]
            if len(paths) == 2:
                source_path, destination_path = paths
                self.move_file_or_folder(source_path, destination_path)
            else:
                self.history_text.insert(tk.END, "Invalid 'move' command. Format: move <source_path> <destination_path>\n")
                self.history_text.see(tk.END)
        elif command.startswith("rename "):
            names = command.split(" ")[1:]
            if len(names) == 2:
                old_name, new_name = names
                self.rename_file_or_folder(old_name, new_name)
            else:
                self.history_text.insert(tk.END, "Invalid 'rename' command. Format: rename <old_name> <new_name>\n")
                self.history_text.see(tk.END)
        elif command.startswith("search "):
            filename = command.split(" ")[1]
            self.search_file(filename)
        elif command.startswith("encrypt "):
            file_to_encrypt = command.split(" ")[1]
            self.encrypt_file(file_to_encrypt)
        elif command.startswith("decrypt "):
            file_to_decrypt = command.split(" ")[1]
            self.decrypt_file(file_to_decrypt)
        elif command == "viewproperties":
            self.view_properties()
        elif command == "sort size":
            self.sort_by_size()
        elif command == "sort name":
            self.sort_by_name()
        elif command == "sort date":
            self.sort_by_date()
        elif command == "sort type":
            self.sort_by_type()
        elif command.startswith("chdir "):
            path = command.split(" ")[1]
            self.change_directory(path)
        elif command == "chdir\\":
            self.move_to_parent_directory()
        else:
            self.history_text.insert(tk.END, f"Unknown command: {command}\n")
            self.history_text.see(tk.END)
            if command.startswith("encrypt "):
              file_to_encrypt = command.split(" ")[1]
              self.encrypt_file(file_to_encrypt)
            elif command.startswith("decrypt "):
              command_parts = command.split(" ")
              if len(command_parts) == 3:
                encrypted_file, output_file = command_parts[1], command_parts[2]
                self.decrypt_file(encrypted_file, output_file)
              else:
                self.history_text.insert(tk.END, "Invalid 'decrypt' command. Format: decrypt <encrypted_file> <output_file>\n")
                self.history_text.see(tk.END)

        # Clear the command entry
        self.command_entry.delete(0, tk.END)

    def open_file(self, file_path):
        try:
            os.startfile(file_path)
            self.history_text.insert(tk.END, f"Opened file: {file_path}\n")
        except Exception as e:
            self.history_text.insert(tk.END, f"Error opening file: {str(e)}\n")
        self.history_text.see(tk.END)
        
    def open_folder(self, folder_name):
        folder_path = os.path.join(self.current_directory, folder_name)
        if os.path.exists(folder_path) and os.path.isdir(folder_path):
            self.current_directory = folder_path
            self.history_text.insert(tk.END, f"Opened folder: {folder_path}\n")
            os.startfile(folder_path)  # Open the folder using the default file explorer
        else:
            self.history_text.insert(tk.END, f"Folder not found: {folder_name}\n")
        self.history_text.see(tk.END)

    def open_folder_or_file(self, path):
        full_path = os.path.join(self.current_directory, path)

        if os.path.exists(full_path):
            if os.path.isdir(full_path):
                self.open_folder(full_path)
            elif os.path.isfile(full_path):
                self.open_file(full_path)
            else:
                self.history_text.insert(tk.END, f"Not a valid file or folder: {path}\n")
        else:
            self.history_text.insert(tk.END, f"File or folder not found: {path}\n")

        self.history_text.see(tk.END)

    def list_directory(self):
        items = os.listdir(self.current_directory)
        items_str = '\t, '.join(items)
        self.history_text.insert(tk.END, f"Contents of {self.current_directory}:\n\t{items_str}\n")
        self.history_text.see(tk.END)

    def delete_file_or_folder(self, file_or_folder):
        path = os.path.join(self.current_directory, file_or_folder)
        try:
            if os.path.exists(path):
                if os.path.isdir(path):
                    os.rmdir(path)
                    self.history_text.insert(tk.END, f"Deleted folder: {path}\n")
                else:
                    os.remove(path)
                    self.history_text.insert(tk.END, f"Deleted file: {path}\n")
            else:
                self.history_text.insert(tk.END, f"File or folder not found: {file_or_folder}\n")
        except Exception as e:
            self.history_text.insert(tk.END, f"Error deleting {file_or_folder}: {str(e)}\n")
        self.history_text.see(tk.END)

    def create_file_or_folder(self, file_or_folder):
        path = os.path.join(self.current_directory, file_or_folder)
        try:
            if "." in file_or_folder:
                # Create a file
                with open(path, 'w') as f:
                    pass
                self.history_text.insert(tk.END, f"Created file: {path}\n")
            else:
                # Create a folder
                os.mkdir(path)
                self.history_text.insert(tk.END, f"Created folder: {path}\n")
        except Exception as e:
            self.history_text.insert(tk.END, f"Error creating {file_or_folder}: {str(e)}\n")
        self.history_text.see(tk.END)

    def move_file_or_folder(self, source_path, destination_path):
        source = os.path.join(self.current_directory, source_path)
        destination = os.path.join(self.current_directory, destination_path)
        try:
            if os.path.exists(source):
                os.rename(source, destination)
                self.history_text.insert(tk.END, f"Moved: {source} to {destination}\n")
            else:
                self.history_text.insert(tk.END, f"Source path not found: {source_path}\n")
        except Exception as e:
            self.history_text.insert(tk.END, f"Error moving: {str(e)}\n")
        self.history_text.see(tk.END)

    def rename_file_or_folder(self, old_name, new_name):
        old_path = os.path.join(self.current_directory, old_name)
        new_path = os.path.join(self.current_directory, new_name)
        try:
            if os.path.exists(old_path):
                os.rename(old_path, new_path)
                self.history_text.insert(tk.END, f"Renamed: {old_path} to {new_path}\n")
            else:
                self.history_text.insert(tk.END, f"File or folder not found: {old_name}\n")
        except Exception as e:
            self.history_text.insert(tk.END, f"Error renaming: {str(e)}\n")
        self.history_text.see(tk.END)

    def search_file(self, filename):
        matches = [f for f in os.listdir(self.current_directory) if filename.lower() in f.lower()]
        if matches:
            self.history_text.insert(tk.END, f"Search results for '{filename}': {', '.join(matches)}\n")
        else:
            self.history_text.insert(tk.END, f"No matches found for '{filename}'\n")
        self.history_text.see(tk.END)

    def change_directory(self, path):
        try:
            os.chdir(path)
            self.current_directory = os.getcwd()
            self.history_text.insert(tk.END, f"Changed directory to: {self.current_directory}\n")
        except Exception as e:
            self.history_text.insert(tk.END, f"Error changing directory: {str(e)}\n")
        self.history_text.see(tk.END)
    
    def move_to_parent_directory(self):
        # Implement your logic to move to the parent directory
        parent_directory = os.path.dirname(self.current_directory)
        os.chdir(parent_directory)
        self.current_directory = os.getcwd()
        self.history_text.insert(tk.END, f"Moved to parent directory: {self.current_directory}\n")
        self.history_text.see(tk.END)
        
    def run_secure_script(filename):
        try:
            # Run the secure.py script with the specified filename
            subprocess.run(["python", "secure.py", filename], check=True)
        except subprocess.CalledProcessError as e:
            print(f"Error running secure.py: {e}")
            sys.exit(1)
    
    def view_properties(self):
        # Implement your logic to display properties of a file or folder
        self.history_text.insert(tk.END, "View Properties command not implemented\n")
        self.history_text.see(tk.END)

    def sort_by_size(self):
        # Implement your logic to sort by size
        self.history_text.insert(tk.END, "Sort by Size command not implemented\n")
        self.history_text.see(tk.END)

    def sort_by_name(self):
        # Implement your logic to sort by name
        self.history_text.insert(tk.END, "Sort by Name command not implemented\n")
        self.history_text.see(tk.END)

    def sort_by_date(self):
        # Implement your logic to sort by date
        self.history_text.insert(tk.END, "Sort by Date command not implemented\n")
        self.history_text.see(tk.END)

    def sort_by_type(self):
        # Implement your logic to sort by type
        self.history_text.insert(tk.END, "Sort by Type command not implemented\n")
        self.history_text.see(tk.END)

    def clear_screen(self):
        self.history_text.delete(1.0, tk.END)
        self.history_text.insert(tk.END, f"Current Directory: {self.current_directory}\n\n")

    def navigate_command_history(self, event):
        # Implement your logic to navigate command history
        self.history_text.insert(tk.END, "Command History Navigation not implemented\n")
        self.history_text.see(tk.END)

def main():
    # Check if the command is "secure" and has a filename
    if len(sys.argv) == 3 and sys.argv[1].lower() == "secure":
        filename = sys.argv[2]
        # Create an instance of CustomCLI and call run_secure_script
        CustomCLI(tk.Tk()).run_secure_script(filename)
    else:
        print("Invalid command. Usage: secure <filename>")
        sys.exit(1)

if __name__ == "_main_":
    root = tk.Tk()
    app = CustomCLI(root)
    root.mainloop()
    main()
