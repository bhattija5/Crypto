import os
import rsa
import hashlib
from cryptography.fernet import Fernet
from Crypto.Cipher import DES
from Crypto.Random import get_random_bytes
import struct
import tkinter as tk
from tkinter import filedialog, messagebox, ttk

# File paths
PUBLIC_KEY_FILE = "public_key.pem"
PRIVATE_KEY_FILE = "private_key.pem"

# --- RSA Key Handling ---
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

# --- Encryption/Decryption Logic ---
def hash_data(data):
    return hashlib.sha256(data).hexdigest()

def pad(data):
    padding_length = 8 - len(data) % 8
    return data + bytes([padding_length]) * padding_length

def unpad(data):
    padding_length = data[-1]
    return data[:-padding_length]

def des_encrypt(data, key):
    cipher = DES.new(key, DES.MODE_ECB)
    return cipher.encrypt(pad(data))

def des_decrypt(encrypted_data, key):
    cipher = DES.new(key, DES.MODE_ECB)
    return unpad(cipher.decrypt(encrypted_data))

def encrypt_file(filepath, public_key, mode="AES"):
    with open(filepath, "rb") as f:
        data = f.read()

    file_hash = hash_data(data)

    if mode == "AES":
        sym_key = Fernet.generate_key()
        encrypted_data = Fernet(sym_key).encrypt(data)
    elif mode == "DES":
        sym_key = get_random_bytes(8)
        encrypted_data = des_encrypt(data, sym_key)
    else:
        raise ValueError("Unsupported encryption mode")

    encrypted_key = rsa.encrypt(sym_key, public_key)

    with open(filepath + f".{mode.lower()}.enc", "wb") as out:
        out.write(struct.pack(">I", len(encrypted_key)))
        out.write(struct.pack(">I", len(file_hash)))
        out.write(encrypted_key)
        out.write(file_hash.encode())
        out.write(encrypted_data)

    return filepath + f".{mode.lower()}.enc"

def decrypt_file(filepath, private_key):
    try:
        with open(filepath, "rb") as f:
            key_len = struct.unpack(">I", f.read(4))[0]
            hash_len = struct.unpack(">I", f.read(4))[0]
            encrypted_key = f.read(key_len)
            original_hash = f.read(hash_len).decode()
            encrypted_data = f.read()

        sym_key = rsa.decrypt(encrypted_key, private_key)

        if filepath.endswith(".aes.enc"):
            decrypted_data = Fernet(sym_key).decrypt(encrypted_data)
        elif filepath.endswith(".des.enc"):
            decrypted_data = des_decrypt(encrypted_data, sym_key)
        else:
            return None, "Unknown encryption type"

        if hash_data(decrypted_data) != original_hash:
            return None, "Hash mismatch! File may be tampered."

        output_path = filepath.replace(".aes.enc", ".decrypted").replace(".des.enc", ".decrypted")
        with open(output_path, "wb") as out:
            out.write(decrypted_data)

        return output_path, "Success"
    except Exception as e:
        return None, f"Unexpected error: {str(e)}"
    



# --- GUI Class ---
class FileEncryptorApp:
    def __init__(self, root):
        self.root = root
        self.root.title("SafeBox - AES | DES | RSA")
        self.root.geometry("450x250")
        self.root.configure(bg="#f7f7f7")

        if not os.path.exists(PUBLIC_KEY_FILE) or not os.path.exists(PRIVATE_KEY_FILE):
            generate_rsa_keys()

        self.public_key, self.private_key = load_rsa_keys()

        # Layout
        main_frame = tk.Frame(root, bg="#f7f7f7", padx=20, pady=20)
        main_frame.pack(fill="both", expand=True)

        tk.Label(main_frame, text="Select Encryption Algorithm:", bg="#f7f7f7", font=("Segoe UI", 10)).pack(pady=5, anchor="w")

        # Algorithm selector
        self.mode_var = tk.StringVar(value="AES")
        self.algorithm_dropdown = ttk.Combobox(main_frame, textvariable=self.mode_var, values=["AES", "DES"], state="readonly")
        self.algorithm_dropdown.pack(pady=5)

        # Encrypt button
        tk.Button(main_frame, text="Encrypt File", width=20, command=self.encrypt_ui).pack(pady=10, padx=5)
        # Decrypt button
        tk.Button(main_frame, text="Decrypt File", width=20, command=self.decrypt_ui).pack(pady=10, padx=5)
        # Regenerate RSA Keys button
        tk.Button(main_frame, text="Regenerate RSA Keys", width=42, command=self.regenerate_keys).pack(pady=(10, 0))

        # Status Label
        self.status_label = tk.Label(root, text="", fg="blue", bg="#f7f7f7", anchor="w", font=("Segoe UI", 9))
        self.status_label.pack(fill="x", padx=20, pady=(0, 10))


    def encrypt_ui(self):
        filepath = filedialog.askopenfilename()
        if not filepath:
            return

        try:
            encrypted_path = encrypt_file(filepath, self.public_key, mode=self.mode_var.get())
            self.status_label.config(text=f"Encrypted: {encrypted_path}")
        except Exception as e:
            messagebox.showerror("Encryption Failed", str(e))
            self.status_label.config(text="Encryption failed.")

    def decrypt_ui(self):
        filepath = filedialog.askopenfilename()
        if not filepath or not (filepath.endswith(".aes.enc") or filepath.endswith(".des.enc")):
            messagebox.showerror("Invalid File", "Please select a valid .aes.enc or .des.enc file.")
            return

        output_path, msg = decrypt_file(filepath, self.private_key)
        if output_path:
            self.status_label.config(text=f"Decrypted to: {output_path}")
            messagebox.showinfo("Decryption Complete", f"Decrypted file saved to: {output_path}")
        else:
            self.status_label.config(text="Decryption failed.")
            messagebox.showerror("Decryption Failed", msg)

    def regenerate_keys(self):
        confirm = messagebox.askyesno("Confirm", "Are you sure you want to regenerate RSA keys?\nOld keys will be replaced!")
        if confirm:
            try:
                generate_rsa_keys()
                self.public_key, self.private_key = load_rsa_keys()
                self.status_label.config(text="RSA keys regenerated successfully.")
                messagebox.showinfo("Keys Regenerated", "New RSA keys have been created and loaded.")
            except Exception as e:
                self.status_label.config(text="Key regeneration failed.")
                messagebox.showerror("Error", f"Failed to regenerate keys: {str(e)}")

# --- Run the app ---
if __name__ == "__main__":
    root = tk.Tk()
    app = FileEncryptorApp(root)
    root.mainloop()
