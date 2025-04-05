import rsa
import os

PUBLIC_KEY_STORAGE = "public_key.pem"
PRIVATE_KEY_STORAGE = "private_key.pem"

def create_and_save_keys():
    public_key, private_key = rsa.newkeys(2048)

    with open(PUBLIC_KEY_STORAGE, 'wb') as pub_file:
        pub_file.write(public_key.save_pkcs1("PEM"))

    with open(PRIVATE_KEY_STORAGE, "wb") as priv_file:
        priv_file.write(private_key.save_pkcs1("PEM"))

    print("Keys generated and saved to files.")

def load_keys():
    if not os.path.exists(PUBLIC_KEY_STORAGE) or not os.path.exists(PRIVATE_KEY_STORAGE):
        print("Key files not found. Generating new ones...")
        create_and_save_keys()

    with open(PUBLIC_KEY_STORAGE, "rb") as pub_file:
        public_key = rsa.PublicKey.load_pkcs1(pub_file.read())

    with open(PRIVATE_KEY_STORAGE, "rb") as priv_file:
        private_key = rsa.PrivateKey.load_pkcs1(priv_file.read())

    return public_key, private_key


def generate_keys():
    (public_key, private_key) = rsa.newkeys(2048)
    return public_key, private_key

def encrypt_mess(message, public_key):
    encrypted_mess = rsa.encrypt(message.encode(), public_key )
    return encrypted_mess

def decrypt_message(encrypted_message, private_key):
    try:
        decrypted_message = rsa.decrypt(encrypted_message, private_key).decode()
        return decrypted_message
    except rsa.DecryptionError:
        return "Decryption failed. Invalid key or message."

if __name__ == "__main__":
    public_key, private_key = load_keys()

    message = "This is a top secret message!"
    print("Original Message:", message)

    encrypted = encrypt_mess(message, public_key)
    print("Encrypted Message:", encrypted)

    decrypted = decrypt_message(encrypted, private_key)
    print("Decrypted Message:", decrypted)