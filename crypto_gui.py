import os
import rsa
import hashlib
from cryptography.fernet import Fernet
import tkinter as tk
from tkinter import filedialog, messagebox, ttk


# File paths for RSA keys
PUBLIC_KEY_FILE = "public_key.pem"
PRIVATE_KEY_FILE = "private_key.pem"

# Generate and save RSA keys
def generate_rsa_keys():
    public_key, private_key = rsa.newkeys(2048)
    with open(PUBLIC_KEY_FILE, "wb") as pub:
        pub.write(public_key.save_pkcs1("PEM"))
    with open(PRIVATE_KEY_FILE, "wb") as priv:
        priv.write(private_key.save_pkcs1("PEM"))

def load_rsa_keys():
    with open(PUBLIC_KEY_FILE, "rb") as pub:
        public_key = rsa.PublicKey.load_pkcs1(pub.read())
    with open(PRIVATE_KEY_FILE, "rb") as priv:
        private_key = rsa.PrivateKey.load_pkcs1(priv.read())
    return public_key, private_key

def hash_data(data):
    return hashlib.sha256(data).hexdigest()

def encrypt_file(filepath, public_key, progress_callback=None):
    with open(filepath, "rb") as f:
        data = f.read()

    file_hash = hash_data(data)
    aes_key = Fernet.generate_key()
    fernet = Fernet(aes_key)
    encrypted_data = fernet.encrypt(data)
    encrypted_key = rsa.encrypt(aes_key, public_key)

    encrypted_file_path = filepath + ".enc"
    with open(encrypted_file_path, "wb") as out:
        out.write(encrypted_key + b"\n" + file_hash.encode() + b"\n" + encrypted_data)

    if progress_callback:
        progress_callback(100)  # Assume 100% completion after encrypting

    return encrypted_file_path

def decrypt_file(filepath, private_key, progress_callback=None):
    try:
        with open(filepath, "rb") as f:
            lines = f.read().split(b"\n", 2)
            if len(lines) < 3:
                return None, "Invalid encrypted file format. Missing sections."

            encrypted_key = lines[0]
            try:
                original_hash = lines[1].decode()
            except UnicodeDecodeError:
                return None, "Could not decode file hash. File may be corrupted or invalid."

            encrypted_data = lines[2]

        try:
            aes_key = rsa.decrypt(encrypted_key, private_key)
        except rsa.DecryptionError:
            return None, "Failed to decrypt AES key. Possibly wrong private key or corrupt file."

        fernet = Fernet(aes_key)
        decrypted_data = fernet.decrypt(encrypted_data)

        new_hash = hash_data(decrypted_data)
        if new_hash != original_hash:
            return None, "Hash mismatch! File may be tampered."

        output_path = filepath.replace(".enc", ".decrypted")
        with open(output_path, "wb") as out:
            out.write(decrypted_data)

        if progress_callback:
            progress_callback(100)  # Assume 100% completion after decrypting

        return output_path, "Success"

    except Exception as e:
        return None, f"Unexpected error: {str(e)}"


# GUI Setup with Progress Bar
class FileEncryptorApp:
    def __init__(self, root):
        self.root = root
        self.root.title("SafeBox - AES | DES | RSA")
        self.root.geometry("450x300")
        self.root.configure(bg="#f7f7f7")

        if not os.path.exists(PUBLIC_KEY_FILE) or not os.path.exists(PRIVATE_KEY_FILE):
            generate_rsa_keys()

        self.public_key, self.private_key = load_rsa_keys()

        # Layout
        main_frame = tk.Frame(root, bg="#f7f7f7", padx=20, pady=20)
        main_frame.pack(fill="both", expand=True)

        # Select Algorithm Label
        tk.Label(main_frame, text="Select Encryption Algorithm:", bg="#f7f7f7", font=("Segoe UI", 10)).pack(pady=5, anchor="w")

        # Algorithm selector
        self.mode_var = tk.StringVar(value="AES")
        self.algorithm_dropdown = ttk.Combobox(main_frame, textvariable=self.mode_var, values=["AES", "DES"], state="readonly")
        self.algorithm_dropdown.pack(pady=5)

        # Encrypt button
        tk.Button(main_frame, text="Encrypt Files", width=20, command=self.encrypt_ui).pack(pady=10, padx=5)
        # Decrypt button
        tk.Button(main_frame, text="Decrypt Files", width=20, command=self.decrypt_ui).pack(pady=10, padx=5)

        # Regenerate RSA Keys button
        tk.Button(main_frame, text="Regenerate RSA Keys", width=42, command=self.regenerate_keys).pack(pady=(10, 0))

        # Progress Bar
        self.progress_bar = ttk.Progressbar(main_frame, length=200, mode='determinate')
        self.progress_bar.pack(pady=10)

        # Status Label
        self.status_label = tk.Label(root, text="", fg="blue", bg="#f7f7f7", anchor="w", font=("Segoe UI", 9))
        self.status_label.pack(fill="x", padx=20, pady=(0, 10))

    def encrypt_ui(self):
        files = filedialog.askopenfilenames()
        if not files:
            return

        total_files = len(files)
        for i, file in enumerate(files, 1):
            self.progress_bar["value"] = (i / total_files) * 100
            self.root.update_idletasks()  # Refresh the GUI
            encrypted_file = encrypt_file(file, self.public_key, progress_callback=self.update_progress)
            messagebox.showinfo("Success", f"File encrypted: {encrypted_file}")
            self.progress_bar["value"] = 0  # Reset progress bar after encryption

    def decrypt_ui(self):
        files = filedialog.askopenfilenames(filetypes=[("Encrypted Files", "*.enc")])
        if not files:
            return

        total_files = len(files)
        for i, file in enumerate(files, 1):
            self.progress_bar["value"] = (i / total_files) * 100
            self.root.update_idletasks()
            output_path, msg = decrypt_file(file, self.private_key, progress_callback=self.update_progress)
            if output_path:
                messagebox.showinfo("Decryption Complete", f"Decrypted to: {output_path}")
            else:
                messagebox.showerror("Decryption Failed", msg)
            self.progress_bar["value"] = 0  # Reset progress bar after decryption

    def update_progress(self, progress):
        self.progress_bar["value"] = progress
        self.root.update_idletasks()

    def regenerate_keys(self):
        generate_rsa_keys()
        self.public_key, self.private_key = load_rsa_keys()
        messagebox.showinfo("Keys Regenerated", "RSA keys have been regenerated successfully.")


if __name__ == "__main__":
    root = tk.Tk()
    app = FileEncryptorApp(root)
    root.mainloop()
