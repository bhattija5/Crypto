import os
import rsa
import hashlib
from cryptography.fernet import Fernet
import tkinter as tk
from tkinter import filedialog, messagebox

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

def encrypt_file(filepath, public_key):
    with open(filepath, "rb") as f:
        data = f.read()

    file_hash = hash_data(data)
    aes_key = Fernet.generate_key()
    fernet = Fernet(aes_key)
    encrypted_data = fernet.encrypt(data)
    encrypted_key = rsa.encrypt(aes_key, public_key)

    with open(filepath + ".enc", "wb") as out:
        out.write(encrypted_key + b"\n" + file_hash.encode() + b"\n" + encrypted_data)

    return filepath + ".enc"

def decrypt_file(filepath, private_key):
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

        return output_path, "Success"

    except Exception as e:
        return None, f"Unexpected error: {str(e)}"

# GUI Setup
class FileEncryptorApp:
    def __init__(self, root):
        self.root = root
        self.root.title("RSA File Encryptor")

        if not os.path.exists(PUBLIC_KEY_FILE) or not os.path.exists(PRIVATE_KEY_FILE):
            generate_rsa_keys()

        self.public_key, self.private_key = load_rsa_keys()

        tk.Button(root, text="Encrypt File", command=self.encrypt_ui).pack(pady=10)
        tk.Button(root, text="Decrypt File", command=self.decrypt_ui).pack(pady=10)

    def encrypt_ui(self):
        filepath = filedialog.askopenfilename()
        if not filepath:
            return
        encrypted_path = encrypt_file(filepath, self.public_key)
        messagebox.showinfo("Success", f"File encrypted: {encrypted_path}")

    def decrypt_ui(self):
        filepath = filedialog.askopenfilename()
        if not filepath or not filepath.endswith(".enc"):
            return
        output_path, msg = decrypt_file(filepath, self.private_key)
        if output_path:
            messagebox.showinfo("Decryption Complete", f"Decrypted to: {output_path}")
        else:
            messagebox.showerror("Decryption Failed", msg)

if __name__ == "__main__":
    root = tk.Tk()
    app = FileEncryptorApp(root)
    root.mainloop()
