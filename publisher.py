import tkinter as tk 
from tkinter import messagebox 
import paho.mqtt.client as mqtt 
import json 
import os 
import time 
import base64 
import hmac
import hashlib
from threading import Timer
import bcrypt 
from Crypto.Cipher import AES 
from Crypto.Random import get_random_bytes
import random 
import string
import socket


# AES Setup
USER_DB = "users.json"
LOG_FILE = "publisher_audit.log"
AES_KEY = base64.b64decode("UAH11A5PTkuqMpB03gMNzg==")
HMAC_KEY = base64.b64decode("iVCj0p6JRySSVXa1RcdeEl4VvuACqGXwMsA21ed2qPQ1==")
MQTT_TOPICS = ["iot/login", "iot/sensor", "iot/control"]
OTP_STORE = {}
OTP_RESEND_COOLDOWN = 30
LOCKOUT_DURATION = 300  # 5 minutes

def pad(text):
    pad_len = 16 - (len(text) % 16)
    return text + (chr(pad_len) * pad_len)

def encrypt_data(data):
    iv = get_random_bytes(16)
    #Generate random IV
    cipher = AES.new(AES_KEY, AES.MODE_CBC, iv)
    pad_len = 16 - len(data) % 16
    padded = data + (chr(pad_len) * pad_len)
    ciphertext = cipher.encrypt(padded.encode())
    mac = hmac.new(HMAC_KEY, iv + ciphertext, hashlib.sha256).digest()
    return base64.b64encode(iv + ciphertext + mac).decode()


# MQTT Config
MQTT_PORT = 1883
MQTT_TOPIC_BASE = "iot/"

# User functions
def load_users():
    if os.path.exists("users.json"):
        with open("users.json", "r") as f:
            return json.load(f)
    return {}

def save_users(users):
    with open("users.json", "w") as f:
        json.dump(users, f, indent=4)

def hash_password(pw):
    return bcrypt.hashpw(pw.encode(), bcrypt.gensalt()).decode()

def check_password(pw, hashed):
    return bcrypt.checkpw(pw.encode(), hashed.encode())


# OTP Setup
otp_store = {}
otp_valid_duration = 30
otp_cooldown = {}
otp_resend_delay = 30

def generate_otp():
    return str(random.randint(100000, 999999))

def send_otp(username):
    current_time = time.time()
    if username in otp_cooldown and current_time - otp_cooldown[username] < otp_resend_delay:
        remaining = int(otp_resend_delay - (current_time - otp_cooldown[username]))
        messagebox.showinfo("OTP Cooldown", f"Wait {remaining} seconds before resending OTP.")
        return
    otp = generate_otp()
    otp_store[username] = {"otp": otp, "time": current_time}
    otp_cooldown[username] = current_time
    messagebox.showinfo("OTP Sent", f"Your OTP is: {otp}")
    start_otp_timer(username)

def start_otp_timer(username):
    def expire_otp():
        if username in otp_store and time.time() - otp_store[username]["time"] >= otp_valid_duration:
            otp_store.pop(username, None)
    Timer(otp_valid_duration, expire_otp).start()

def verify_otp(username, user_input):
    if username not in otp_store:
        messagebox.showerror("Error", "No OTP sent or expired.")
        return False
    entry = otp_store[username]
    if time.time() - entry["time"] > otp_valid_duration:
        messagebox.showerror("Error", "OTP expired")
        otp_store.pop(username, None)
        return False
    if user_input == entry["otp"]:
        otp_store.pop(username, None)
        return True
    messagebox.showerror("Error", "Invalid OTP")
    return False

def get_ip():
    return socket.gethostbyname(socket.gethostname())

def log_event(username, action, topic="N/A", encrypted_msg=None):
    timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
    users = load_users()
    role = users[username]["role"] if username in users else "unknown"
    ip = get_ip()
    with open("publisher.audit.log", "a") as f:
        f.write(f"[{timestamp}] {username}: {role} | {action} | Topic: {topic} | IP: {ip}")
        if encrypted_msg:
            f.write(f" | Encrypted Message: {encrypted_msg}")
        f.write("\n")


# GUI State
entry_username = None
entry_password = None
entry_confirm_password = None
entry_otp = None
toggle_btn = None
toggle_otp_btn = None
role_var = None

# GUI Functions
def show_initial_screen():
    for widget in window.winfo_children():
        widget.pack_forget()
    window.configure(bg="#f7f7f7")

    tk.Label(window, text="Username:", font=("Helvetica", 16), bg="#f7f7f7").pack(pady=5)
    global entry_username
    entry_username = tk.Entry(window, relief="solid")
    entry_username.pack(pady=10)

    tk.Label(window, text="Password:", font=("Helvetica", 16),bg="#f7f7f7").pack(pady=5)
    global entry_password
    entry_password = tk.Entry(window, show="*", relief="solid")
    entry_password.pack(pady=10)

    global toggle_btn
    toggle_btn = tk.Button(window, text="👁", command=toggle_password_visibility)
    toggle_btn.pack(pady=5)

    tk.Button(window, text="Log In", font=("Helvetica", 16),bg="#2196F3", fg="white", command=handle_login, relief="solid").pack(pady=10, fill="x", padx=50)
    tk.Button(window, text="Sign Up", font=("Helvetica", 16), bg="#4CAF50", fg="white", command=show_signup_screen, relief="solid").pack(pady=10, fill="x", padx=50)
    tk.Button(window, text="Forgot Password",font=("Helvetica", 16),  bg="#FF9800", fg="white", command=show_forgot_password_screen, relief="solid").pack(pady=10, fill="x", padx=50)


def toggle_password_visibility():
    if entry_password.cget('show') == "":
        entry_password.config(show="*")
        toggle_btn.config(text="👁")
    else:
        entry_password.config(show="")
        toggle_btn.config(text="🙈")

def show_signup_screen():
    for widget in window.winfo_children():
        widget.pack_forget()
    
    window.configure(bg="#f7f7f7")

    tk.Label(window, text="Create Account", font=("Helvetica", 16, "bold"), bg="#f7f7f7", fg="#333").pack(pady=20)
    
    # Username field
    tk.Label(window, text="Username:", font=("Helvetica", 12), bg="#f7f7f7").pack(pady=5)
    global entry_username
    entry_username = tk.Entry(window, font=("Helvetica", 12), bd=2, relief="solid")
    entry_username.pack(pady=10, ipadx=5, ipady=5)

    # Password field
    tk.Label(window, text="Password:", font=("Helvetica", 12), bg="#f7f7f7").pack(pady=5)
    global entry_password
    entry_password = tk.Entry(window, show="*", font=("Helvetica", 12), bd=2, relief="solid")
    entry_password.pack(pady=10, ipadx=5, ipady=5)

    # Confirm Password field
    tk.Label(window, text="Confirm Password:", font=("Helvetica", 12), bg="#f7f7f7").pack(pady=5)
    global entry_confirm_password
    entry_confirm_password = tk.Entry(window, show="*", font=("Helvetica", 12), bd=2, relief="solid")
    entry_confirm_password.pack(pady=10, ipadx=5, ipady=5)

    # Toggle eye for password fields
    def toggle_signup_passwords():
        if entry_password.cget("show") == "*":
            entry_password.config(show="")
            entry_confirm_password.config(show="")
            pw_toggle_btn.config(text="🙈")
        else:
            entry_password.config(show="*")
            entry_confirm_password.config(show="*")
            pw_toggle_btn.config(text="👁")

    pw_toggle_btn = tk.Button(window, text="👁", command=toggle_signup_passwords)
    pw_toggle_btn.pack()

    # Role selection
    global role_var
    role_var = tk.StringVar()
    role_var.set("sensor")
    tk.Label(window, text="Select Role:", font=("Helvetica", 12), bg="#f7f7f7").pack(pady=5)
    tk.OptionMenu(window, role_var,"Login", "admin", "sensor", "viewer").pack(pady=10, ipadx=5)

    # Sign up button
    tk.Button(window, text="Sign Up", font=("Helvetica", 12), bg="#4CAF50", fg="white", command=handle_sign_up, relief="solid").pack(pady=15, fill="x", padx=50)
    
    # Back button
    tk.Button(window, text="Back", font=("Helvetica", 12), bg="#f44336", fg="white", command=switch_to_login_screen, relief="solid").pack(pady=10, fill="x", padx=50)


   
def show_forgot_password_screen():
    for widget in window.winfo_children():
        widget.pack_forget()

    window.configure(bg="#f7f7f7")

    tk.Label(window, text="Forgot Password", font=("Helvetica", 20, "bold"), bg="#f7f7f7", fg="#333").pack(pady=20)

    tk.Label(window, text="Enter Username:", font=("Helvetica", 16), bg="#f7f7f7").pack(pady=5,)
    username_entry = tk.Entry(window)
    username_entry.pack(pady=10)

    def initiate_reset():
        username = username_entry.get().strip()
        users = load_users()
        if username not in users:
            messagebox.showerror("Error", "Username not found")
            return
        send_otp(username)
        show_reset_password_otp_screen(username)

    tk.Button(window, text="Send OTP", font=("Helvetica", 16), bg="#FF9800", fg="white", command=initiate_reset).pack(pady=10, fill="x", padx=50)
    tk.Button(window, text="Back", font=("Helvetica", 16), bg="#f44336", fg="white", command=switch_to_login_screen).pack(pady=5, fill="x", padx=50)

def show_reset_password_otp_screen(username):
    for widget in window.winfo_children():
        widget.pack_forget()

    window.configure(bg="#f7f7f7")


    tk.Label(window, text="Enter OTP to Reset Password:", font=("Helvetica", 12), bg="#f7f7f7").pack(pady=5)
    global entry_otp_reset
    entry_otp_reset = tk.Entry(window, show="*", font=("Helvetica", 12), bd=2, relief="solid")
    entry_otp_reset.pack(pady=10, ipadx=5, ipady=5)

    def toggle_reset_otp():
        if entry_otp_reset.cget("show") == "*":
            entry_otp_reset.config(show="")
            otp_toggle_btn.config(text="🙈")
        else:
            entry_otp_reset.config(show="*")
            otp_toggle_btn.config(text="👁")

    otp_toggle_btn = tk.Button(window, text="👁", command=toggle_reset_otp)
    otp_toggle_btn.pack()

    # New and Confirm Password
        # Password field
    tk.Label(window, text="New Password:", font=("Helvetica", 12), bg="#f7f7f7").pack(pady=5)
    global entry_password
    entry_password = tk.Entry(window, show="*", font=("Helvetica", 12), bd=2, relief="solid")
    entry_password.pack(pady=10, ipadx=5, ipady=5)

    # Confirm Password field
    tk.Label(window, text="Confirm Password:", font=("Helvetica", 12), bg="#f7f7f7").pack(pady=5)
    global entry_confirm_password
    entry_confirm_password = tk.Entry(window, show="*", font=("Helvetica", 12), bd=2, relief="solid")
    entry_confirm_password.pack(pady=10, ipadx=5, ipady=5)

   # Toggle eye for password fields
    def toggle_signup_passwords():
        if entry_password.cget("show") == "*":
            entry_password.config(show="")
            entry_confirm_password.config(show="")
            pw_toggle_btn.config(text="🙈")
        else:
            entry_password.config(show="*")
            entry_confirm_password.config(show="*")
            pw_toggle_btn.config(text="👁")

    pw_toggle_btn = tk.Button(window, text="👁", command=toggle_signup_passwords)
    pw_toggle_btn.pack()


    def verify_otp_and_reset():
        otp = entry_otp_reset.get().strip()
        new_pw = entry_password.get().strip()
        confirm_pw = entry_confirm_password.get().strip()
        if new_pw != confirm_pw:
            messagebox.showerror("Error", "Passwords do not match")
            return
        if verify_otp(username, otp):
            users = load_users()
            users[username]["password"] = hash_password(new_pw)
            save_users(users)
            messagebox.showinfo("Success", "Password reset successful!")
            show_initial_screen()



     # Reset Password button
    tk.Button(window, text="Reset Password", font=("Helvetica", 16), bg="#4CAF50", fg="white", command=verify_otp_and_reset, relief="solid").pack(pady=15, fill="x", padx=50)
    
    # Resend otp button
    tk.Button(window, text="Resend OTP", font=("Helvetica", 16), bg="#f44336", fg="white", command=lambda: send_otp(username), relief="solid").pack(pady=10, fill="x", padx=50)

  # Back button
    tk.Button(window, text="Back", font=("Helvetica", 16), bg="#FF9800", fg="white", command=switch_to_login_screen, relief="solid").pack(pady=15, fill="x", padx=50)




def switch_to_login_screen():
    show_initial_screen()

def handle_sign_up():
    username = entry_username.get().strip()
    password = entry_password.get().strip()
    confirm_password = entry_confirm_password.get().strip()
    role = role_var.get()
    if not username or not password or not confirm_password:
        messagebox.showerror("Error", "Please fill all fields")
        return
    if password != confirm_password:
        messagebox.showerror("Error", "Passwords do not match")
        return
    users = load_users()
    if username in users:
        messagebox.showerror("Error", "User already exists")
        return
    send_otp(username)
    show_otp_verification_screen(username, password, role)

def show_otp_verification_screen(username, password, role):
    for widget in window.winfo_children():
        widget.pack_forget()
    tk.Label(window, text="Enter OTP sent to you:").pack(pady=10)
    global entry_otp
    entry_otp = tk.Entry(window, show="*")
    entry_otp.pack(pady=5)

    def toggle_otp():
        if entry_otp.cget('show') == "*":
            entry_otp.config(show="")
            toggle_otp_btn.config(text="🙈")
        else:
            entry_otp.config(show="*")
            toggle_otp_btn.config(text="👁")

    global toggle_otp_btn
    toggle_otp_btn = tk.Button(window, text="👁", command=toggle_otp)
    toggle_otp_btn.pack()

    def verify_and_register():
        otp = entry_otp.get().strip()
        if verify_otp(username, otp):
            users = load_users()
            users[username] = {"password": hash_password(password), "role": role, "attempts": 0, "lock_time": 0}
            save_users(users)
            messagebox.showinfo("Success", "Registration complete!")
            show_initial_screen()

    tk.Button(window, text="Verify OTP", command=verify_and_register).pack(pady=5)
    tk.Button(window, text="Resend OTP", command=lambda: send_otp(username)).pack(pady=5)
# Add the following modifications to integrate role-based access control:

# Role-based topic selection and permissions
def show_publish_interface(username, role):
    for widget in window.winfo_children():
        widget.pack_forget()
    window.configure(bg="lightblue")

    # Show welcome message with role
    tk.Label(window, text=f"Welcome {username} ({role})", bg="lightblue", font=("Helvetica", 16)).pack(pady=10)

    # Broker entry
    tk.Label(window, text="Broker:",  font=("Helvetica", 16), bg="lightblue").pack()
    broker_entry = tk.Entry(window)
    broker_entry.insert(0, "localhost")
    broker_entry.pack()

    # Topic selection based on user role
    tk.Label(window, text="Topic:", font=("Helvetica", 16), bg="lightblue").pack()
    selected_topic = tk.StringVar()

    if role == "admin":
        topics = [MQTT_TOPIC_BASE + r for r in ["login", "sensor", "control", "admin"]]
    elif role == "sensor":
        topics = [MQTT_TOPIC_BASE + r for r in ["sensor", "control"]]
    elif role == "viewer":
        topics = [MQTT_TOPIC_BASE + r for r in ["sensor"]]
        
    selected_topic.set(topics[0])  # Set default topic based on role
    tk.OptionMenu(window, selected_topic, *topics).pack()

    # Message entry
    tk.Label(window, text="Message:", bg="lightblue", font=("Helvetica", 16)).pack()
    message_entry = tk.Text(window, height=10, width=50)  # Adjusted height and width
    message_entry.pack(pady=5)

    # Publish function based on role
    def publish():
        topic = selected_topic.get()
        message = message_entry.get("1.0", "end-1c").strip()  # Get the text from the Text widget
        broker = broker_entry.get().strip()
        
        # Check role-based permissions to publish
        if role == "viewer":
            messagebox.showerror("Access Denied", "You do not have permission to publish.")
            return
        
        if not message:
            messagebox.showerror("Error", "Enter a message")
            return
        
        try:
            encrypted_msg = encrypt_data(message)
            client = mqtt.Client()
            client.connect(broker, MQTT_PORT, 60)
            client.loop_start()
            client.publish(topic, encrypted_msg)
            log_event(username, "Publish", topic, encrypted_msg)
            messagebox.showinfo("Published", "Encrypted message sent!")
            show_final_interface(username)
        except Exception as e:
            messagebox.showerror("MQTT Error", str(e))

    tk.Button(window, text="Publish",  command=publish, font=("Helvetica", 16), bg="#4CAF50", fg="white").pack(pady=10, fill="x", padx=50)
    tk.Button(window, text="Back", command=show_initial_screen, font=("Helvetica", 16), bg="#f44336", fg="white").pack(pady=5, fill="x", padx=50)

# Adjust role-based access control in login flow
def handle_login():
    username = entry_username.get().strip()
    password = entry_password.get().strip()

    if not username or not password:
        messagebox.showerror("Error", "Please enter both username and password.")
        return

    users = load_users()

    if username not in users:
        messagebox.showerror("Login Failed", "User not found.")
        return

    user = users[username]

    # Check lockout status
    if time.time() < user.get("lock_time", 0):
        remaining = int(user["lock_time"] - time.time())
        messagebox.showerror("Account Locked", f"Try again in {remaining} seconds.")
        return

    # bcrypt password check
    if not bcrypt.checkpw(password.encode(), user["password"].encode()):
        user["attempts"] = user.get("attempts", 0) + 1
        if user["attempts"] >= 3:
            user["lock_time"] = time.time() + 300
            save_users(users)
            messagebox.showerror("Locked", "Too many failed attempts. Account locked for 5 minutes.")
        else:
            save_users(users)
            messagebox.showerror("Login Failed", f"Incorrect password. Attempts: {user['attempts']}/3")
        return

    # Success: reset lockout
    user["attempts"] = 0
    user["lock_time"] = 0
    save_users(users)

    role = user["role"]
    log_event(username, "Login")
    show_publish_interface(username, role)

def show_final_interface(username):
    for widget in window.winfo_children():
        widget.pack_forget()
    tk.Label(window, text=f"Welcome {username}", bg="lightgray", font=("Helvetica", 25)).pack(pady=20)
    tk.Button(window, text="Logout", command=show_initial_screen, bg="#FF9800", font=("Helvetica", 15), fg="white").pack(pady=10, fill="x", padx=50)
    tk.Button(window, text="Delete Account", command=lambda: delete_account(username), bg="#f44336", font=("Helvetica", 15), fg="white").pack(pady=10, fill="x", padx=50)

def delete_account(username):
    users = load_users()
    if username in users:
        del users[username]
        save_users(users)
        messagebox.showinfo("Deleted", "Account removed.")
    show_initial_screen()

# Start GUI
window = tk.Tk()
window.title("Secure MQTT Login System")
window.geometry("400x600")
show_initial_screen()
window.mainloop()
