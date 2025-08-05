from cryptography.fernet import Fernet
import os

# -----------------------------
# Generate and print encryption key
# -----------------------------
def generate_key():
    key = Fernet.generate_key()
    print("\n[+] Encryption Key (Save this securely):")
    print(key.decode())  # show as string for copy-paste
    return key
# -----------------------------
# Encrypt a single file
# -----------------------------
def encrypt_file(file_path, key):
    fernet = Fernet(key)
    with open(file_path, "rb") as file:
        data = file.read()
    encrypted = fernet.encrypt(data)
    with open(file_path, "wb") as file:
        file.write(encrypted)
    print(f"[Encrypted] {file_path}")

# -----------------------------
# Decrypt a single file
# -----------------------------
def decrypt_file(file_path, fernet):
    with open(file_path, "rb") as file:
        encrypted_data = file.read()
    try:
        decrypted = fernet.decrypt(encrypted_data)
        with open(file_path, "wb") as file:
            file.write(decrypted)
        print(f"[Decrypted] {file_path}")
    except:
        print(f"[!] Skipped: {file_path} (Invalid or already decrypted)")

# -----------------------------
# Encrypt all files in folder
# -----------------------------
def encrypt_folder(folder_path):
    key = generate_key()
    print("\n[*] Starting Encryption...")
    for root, _, files in os.walk(folder_path):
        for filename in files:
            file_path = os.path.join(root, filename)
            encrypt_file(file_path, key)
    print("\n[✔] All files encrypted.")

# -----------------------------
# Decrypt all files in folder 
# -----------------------------
def decrypt_folder(folder_path):
    key_input = input("\nEnter the encryption key: ").strip()
    try:
        fernet = Fernet(key_input.encode())
    except:
        print("[-] Invalid key format.")
        return

    print("\n[*] Starting Decryption...")
    for root, _, files in os.walk(folder_path):
        for filename in files:
            file_path = os.path.join(root, filename)
            decrypt_file(file_path, fernet)
    print("\n[✔] Decryption completed.")

# -----------------------------
# Main Driver
# -----------------------------
if __name__ == "__main__":
    folder = input("Enter full path of the folder to process: ").strip()
    if not os.path.isdir(folder):
        print("[-] Invalid folder path.")
        exit()

    choice = input("Do you want to (E)ncrypt or (D)ecrypt? ").strip().upper()
    if choice == 'E':
        encrypt_folder(folder)
    elif choice == 'D':
        decrypt_folder(folder)
    else:
        print("[-] Invalid option. Choose E or D.")
