def open_file(self, file_path):
        try:
            os.startfile(file_path)
            self.history_text.insert(tk.END, f"Opened file: {file_path}\n")
        except Exception as e:
            self.history_text.insert(tk.END, f"Error opening file: {str(e)}\n")
        self.history_text.see(tk.END)