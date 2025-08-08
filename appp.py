import os
import json
import re
import bcrypt
import smtplib
import tempfile
import webbrowser
from cryptography.fernet import Fernet
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import tkinter as tk
from tkinter import filedialog, messagebox
from PIL import Image, ImageTk

# ---------------- Config & Paths ----------------
USERS_FILE = "users.json"
STYLE = {
    "bg_color": "white",
    "font_header": ("Helvetica", 16, "bold"),
    "font_button": ("Arial", 12, "bold"),
    "font_label": ("Helvetica", 10, "bold"),
    "font_entry": ("Consolas", 10),
    "btn_normal": {
        "width": 25,
        "height": 2,
        "font": ("Arial", 12, "bold"),
        "bg": "orange",
        "fg": "black",
        "activebackground": "orange",
        "activeforeground": "white"
    },
    "popup_btn": {
        "bg": "#007BFF",
        "fg": "white",
        "font": ("Arial", 10, "bold"),
        "activebackground": "#0056b3"
    },
    "encrypt_btn": {
        "bg": "#28a745",
        "fg": "white",
        "font": ("Arial", 12, "bold"),
        "activebackground": "#1e7e34"
    }
}

# ---------------- Embedded HTML ----------------
PROJECT_INFO_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Project Information</title>
    <style>
        body { font-family: Arial, sans-serif; padding: 40px; line-height: 1.6; }
        .header { display: flex; justify-content: space-between; align-items: center; }
        .header img { width: 120px; }
        h1 { color: #000; font-size: 26px; }
        table { width: 100%; border-collapse: collapse; margin-top: 12px; }
        th, td { border: 1px solid #ccc; padding: 8px 12px; text-align: left; }
        th { background-color: #f2f2f2; }
        .section-title { margin-top: 30px; font-size: 18px; font-weight: bold; text-transform: uppercase; }
        .highlight { font-weight: bold; }
        .note { margin-top: 10px; font-size: 15px; }
    </style>
</head>
<body>
    <div class="header">
        <h1>Project Information</h1>
        <img src="download.png" alt="Logo">
    </div>
    <p class="note">
        This project was developed by <span class="highlight">Team 21</span> as part of a 
        <span class="highlight">Cyber Security Internship</span>. This project is designed to 
        <span class="highlight">safeguard the user folder details by encrypting it using AES Algorithm.</span>
    </p>
    <div class="section-title">Project Details</div>
    <table>
        <tr><th>Project Name</th><td>Folder Encryption using AES</td></tr>
        <tr><th>Project Description</th><td>Implementing AES Encryption for Folders which Contain Secured Data</td></tr>
        <tr><th>Project Start Date</th><td>02-MAY-2025</td></tr>
        <tr><th>Project End Date</th><td>02-JUL-2025</td></tr>
        <tr><th>Project Status</th><td>Completed</td></tr>
    </table>
    <div class="section-title">Developer Details</div>
    <table>
        <tr><th>Name</th><th>Employee ID</th><th>Email</th></tr>
        <tr><td>J.Sai Raj</td><td>ST#IS#0000</td><td>@gmail.com</td></tr>
        <tr><td>P.Sai Charan</td><td>ST#IS#0000</td><td>@gmail.com</td></tr>
        <tr><td>Dhanush</td><td>ST#IS#0000</td><td>@gmail.com</td></tr>
        <tr><td>M.Susheel Kumar</td><td>ST#IS#7432</td><td>susheelmemula@gmail.com</td></tr>
    </table>
    <div class="section-title">Company Details</div>
    <table>
        <tr><th>Company Name</th><td>SUPRAJA TECHNOLOGIES</td></tr>
        <tr><th>Website</th><td>www.suprajatech.com</td></tr>
        <tr><th>Location</th><td>Hyderabad, Telangana</td></tr>
        <tr><th>Contact</th><td>‪+91 9550055338‬ / ‪+91 7901336873‬</td></tr>
        <tr><th>Email</th><td>contact@suprajatechnologies.com</td></tr>
    </table>
</body>
</html>"""

# ---------------- Utility functions ----------------
def ensure_users_file():
    if not os.path.exists(USERS_FILE):
        with open(USERS_FILE, "w", encoding="utf-8") as f:
            json.dump({}, f, indent=4)

def load_users():
    ensure_users_file()
    with open(USERS_FILE, "r", encoding="utf-8") as f:
        try:
            return json.load(f)
        except json.JSONDecodeError:
            return {}

def save_users(users_dict):
    with open(USERS_FILE, "w", encoding="utf-8") as f:
        json.dump(users_dict, f, indent=4)

def is_valid_email(email):
    pattern = r"[^@]+@[^@]+\.[^@]+"
    return re.match(pattern, email)

def browse_folder(entry_field):
    folder_path = filedialog.askdirectory()
    if folder_path:
        entry_field.delete(0, tk.END)
        entry_field.insert(0, folder_path)

def load_logo_image(parent, path=".\logo.png"):
    try:
        if os.path.exists(path):
            logo_img = Image.open(path)
            logo_img = logo_img.resize((160, 160))
            photo = ImageTk.PhotoImage(logo_img)
            label = tk.Label(parent, image=photo, bg=STYLE["bg_color"])
            label.image = photo
            label.pack(pady=10)
        else:
            tk.Label(parent, text="(Logo not found)", bg=STYLE["bg_color"], fg="gray").pack(pady=10)
    except Exception:
        tk.Label(parent, text="(Image load error)", bg=STYLE["bg_color"], fg="gray").pack(pady=10)

# ---------------- Auth functions ----------------
def register_user(username, password):
    if not username or not password:
        raise ValueError("Username and password required.")
    users = load_users()
    if username in users:
        raise ValueError("Username already exists.")
    hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
    users[username] = {"password": hashed}
    save_users(users)

def validate_user(username, password):
    users = load_users()
    if username not in users:
        return False
    stored_hash = users[username].get("password", "").encode()
    try:
        return bcrypt.checkpw(password.encode(), stored_hash)
    except Exception:
        return False

# ---------------- Encryption / Email ----------------
def encrypt_folder_and_send_key(folder, sender_email, smtp_password, receiver_email):
    if not os.path.isdir(folder):
        raise FileNotFoundError("Folder not found.")

    key = Fernet.generate_key()
    fernet = Fernet(key)

    for root, _, files in os.walk(folder):
        for fname in files:
            file_path = os.path.join(root, fname)
            if os.path.abspath(file_path) == os.path.abspath(USERS_FILE):
                continue
            with open(file_path, "rb") as rf:
                data = rf.read()
            enc = fernet.encrypt(data)
            with open(file_path, "wb") as wf:
                wf.write(enc)

    subject = "AES Encryption Key (Folder Encryptor)"
    body = (
        "Hello,\n\n"
        "Your folder has been encrypted successfully. Keep this key safe to decrypt files.\n\n"
        f"{key.decode()}\n\n"
        "Do NOT share this key with others.\n"
    )

    msg = MIMEMultipart()
    msg["From"] = sender_email
    msg["To"] = receiver_email
    msg["Subject"] = subject
    msg.attach(MIMEText(body, "plain"))

    server = smtplib.SMTP("smtp.gmail.com", 587)
    server.starttls()
    server.login(sender_email, smtp_password)
    server.send_message(msg)
    server.quit()

    return key.decode()

def decrypt_folder(folder, key_text):
    if not os.path.isdir(folder):
        raise FileNotFoundError("Folder not found.")

    fernet = Fernet(key_text.encode())
    for root, _, files in os.walk(folder):
        for fname in files:
            file_path = os.path.join(root, fname)
            if os.path.abspath(file_path) == os.path.abspath(USERS_FILE):
                continue
            with open(file_path, "rb") as rf:
                data = rf.read()
            try:
                dec = fernet.decrypt(data)
            except Exception:
                continue
            with open(file_path, "wb") as wf:
                wf.write(dec)

# ---------------- GUI Popups ----------------
def open_encrypt_popup(parent):
    popup = tk.Toplevel(parent)
    popup.title("🔐 Encrypt Folder & Email Key")
    popup.configure(bg=STYLE["bg_color"])
    popup.geometry("560x360")
    popup.resizable(False, False)
    popup.grab_set()

    label_style = {"bg": STYLE["bg_color"], "fg": "#333", "font": STYLE["font_label"]}
    entry_style = {"width": 45, "font": STYLE["font_entry"]}

    tk.Label(popup, text="📁 Folder:", **label_style).grid(row=0, column=0, padx=10, pady=10, sticky="w")
    folder_entry = tk.Entry(popup, **entry_style)
    folder_entry.grid(row=0, column=1)
    tk.Button(popup, text="Browse", command=lambda: browse_folder(folder_entry), **STYLE["popup_btn"]).grid(row=0, column=2, padx=5)

    tk.Label(popup, text="📤 Sender Email:", **label_style).grid(row=1, column=0, padx=10, pady=8, sticky="w")
    sender_entry = tk.Entry(popup, **entry_style)
    sender_entry.grid(row=1, column=1, columnspan=2)

    tk.Label(popup, text="🔑 SMTP Password:", **label_style).grid(row=2, column=0, padx=10, pady=8, sticky="w")
    password_entry = tk.Entry(popup, show="*", **entry_style)
    password_entry.grid(row=2, column=1, columnspan=2)

    tk.Label(popup, text="📥 Receiver Email:", **label_style).grid(row=3, column=0, padx=10, pady=8, sticky="w")
    receiver_entry = tk.Entry(popup, **entry_style)
    receiver_entry.grid(row=3, column=1, columnspan=2)

    def on_encrypt():
        folder = folder_entry.get().strip()
        sender = sender_entry.get().strip()
        pwd = password_entry.get().strip()
        receiver = receiver_entry.get().strip()

        if not all([folder, sender, pwd, receiver]):
            messagebox.showerror("Missing Info", "Please fill all fields.")
            return
        if not is_valid_email(sender) or not is_valid_email(receiver):
            messagebox.showerror("Invalid Email", "Please enter valid emails.")
            return
        try:
            key = encrypt_folder_and_send_key(folder, sender, pwd, receiver)
            messagebox.showinfo("Success", f"Folder encrypted. Key emailed to {receiver}.\n\n(You may also copy key now.)")
            if messagebox.askyesno("Copy Key", "Do you want to copy the key to clipboard?"):
                popup.clipboard_clear()
                popup.clipboard_append(key)
            popup.destroy()
        except Exception as e:
            messagebox.showerror("Error", f"Encryption/Email failed: {e}")

    tk.Button(popup, text="🔐 Encrypt", command=on_encrypt, **STYLE["encrypt_btn"]).grid(row=5, column=1, pady=20)

def open_decrypt_popup(parent):
    popup = tk.Toplevel(parent)
    popup.title("🔓 Decrypt Folder")
    popup.configure(bg=STYLE["bg_color"])
    popup.geometry("520x220")
    popup.resizable(False, False)
    popup.grab_set()

    label_style = {"bg": STYLE["bg_color"], "fg": "#333", "font": STYLE["font_label"]}
    entry_style = {"width": 45, "font": STYLE["font_entry"]}

    tk.Label(popup, text="📁 Folder:", **label_style).grid(row=0, column=0, padx=10, pady=10, sticky="w")
    folder_entry = tk.Entry(popup, **entry_style)
    folder_entry.grid(row=0, column=1)
    tk.Button(popup, text="Browse", command=lambda: browse_folder(folder_entry), **STYLE["popup_btn"]).grid(row=0, column=2, padx=5)

    tk.Label(popup, text="🔑 AES Key:", **label_style).grid(row=1, column=0, padx=10, pady=10, sticky="w")
    key_entry = tk.Entry(popup, **entry_style)
    key_entry.grid(row=1, column=1, columnspan=2)

    def on_decrypt():
        folder = folder_entry.get().strip()
        key = key_entry.get().strip()
        if not folder or not key:
            messagebox.showerror("Missing Info", "Provide folder path and key.")
            return
        try:
            decrypt_folder(folder, key)
            messagebox.showinfo("Success", "Decryption complete.")
            popup.destroy()
        except Exception as e:
            messagebox.showerror("Error", f"Decryption failed: {e}")

    tk.Button(popup, text="🔓 Decrypt", command=on_decrypt, **STYLE["encrypt_btn"]).grid(row=3, column=1, pady=20)

# ---------------- Main GUI ----------------
def main_gui(logged_user):
    root = tk.Tk()
    root.title(f"🛡 Folder Encryptor - {logged_user}")
    root.geometry("640x560")
    root.configure(bg=STYLE["bg_color"])
    root.resizable(False, False)

    tk.Label(root, text="🔐 Folder Encryption Tool", bg=STYLE["bg_color"], fg="black", font=STYLE["font_header"]).pack(pady=12)
    load_logo_image(root)

    def show_project_info():
        tmp_file = tempfile.NamedTemporaryFile(delete=False, suffix=".html")
        tmp_file.write(PROJECT_INFO_HTML.encode("utf-8"))
        tmp_file.close()
        webbrowser.open(f"file://{tmp_file.name}")

    tk.Button(root, text="📄 Project Info", command=show_project_info, **STYLE["btn_normal"]).pack(pady=8)
    tk.Button(root, text="🔐 Encrypt Folder", command=lambda: open_encrypt_popup(root), **STYLE["btn_normal"]).pack(pady=10)
    tk.Button(root, text="🔓 Decrypt Folder", command=lambda: open_decrypt_popup(root), **STYLE["btn_normal"]).pack(pady=10)
    tk.Button(root, text="Logout", command=lambda: (root.destroy(), login_screen()), **STYLE["btn_normal"]).pack(pady=20)

    root.mainloop()

# ---------------- Login / Signup UI ----------------
def login_screen():
    login_win = tk.Tk()
    login_win.title("Login or Sign Up")
    login_win.geometry("380x260")
    login_win.configure(bg=STYLE["bg_color"])
    login_win.resizable(False, False)

    tk.Label(login_win, text="Welcome — Sign In or Create Account", bg=STYLE["bg_color"], font=("Helvetica", 12, "bold")).pack(pady=8)
    tk.Label(login_win, text="Username:", bg=STYLE["bg_color"]).pack(pady=(8,0))
    username_entry = tk.Entry(login_win, width=30)
    username_entry.pack()
    tk.Label(login_win, text="Password:", bg=STYLE["bg_color"]).pack(pady=(8,0))
    password_entry = tk.Entry(login_win, width=30, show="*")
    password_entry.pack()

    def do_login():
        user = username_entry.get().strip()
        pwd = password_entry.get().strip()
        if not user or not pwd:
            messagebox.showerror("Missing", "Provide username and password.")
            return
        if validate_user(user, pwd):
            login_win.destroy()
            main_gui(user)
        else:
            messagebox.showerror("Failed", "Invalid username or password.")

    def do_signup():
        user = username_entry.get().strip()
        pwd = password_entry.get().strip()
        if not user or not pwd:
            messagebox.showerror("Missing", "Provide username and password to sign up.")
            return
        try:
            register_user(user, pwd)
            messagebox.showinfo("Success", "Account created — you can now log in.")
        except ValueError as ve:
            messagebox.showerror("Error", str(ve))
        except Exception as e:
            messagebox.showerror("Error", f"Registration failed: {e}")

    btn_frame = tk.Frame(login_win, bg=STYLE["bg_color"])
    btn_frame.pack(pady=12)
    tk.Button(btn_frame, text="Login", command=do_login, bg="#28a745", fg="white", width=12).grid(row=0, column=0, padx=6)
    tk.Button(btn_frame, text="Sign Up", command=do_signup, bg="#007BFF", fg="white", width=12).grid(row=0, column=1, padx=6)

    tk.Label(login_win, text="(We hash your password locally with bcrypt)", bg=STYLE["bg_color"], fg="gray").pack(pady=(6,0))
    login_win.mainloop()

# ---------------- Start ----------------
if __name__ == "__main__":
    ensure_users_file()
    login_screen()
