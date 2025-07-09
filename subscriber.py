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


# Configurations
AES_KEY = base64.b64decode("UAH11A5PTkuqMpB03gMNzg==")
HMAC_KEY = base64.b64decode("iVCj0p6JRySSVXa1RcdeEl4VvuACqGXwMsA21ed2qPQ1==")
USER_DB = "users.json"
LOG_FILE = "subscriber_audit.log"
LOCKOUT_DURATION = 300
OTP_EXPIRY = 30
OTP_STORE = {}

ROLE_TOPICS = {
    "admin": ["iot/login", "iot/sensor", "iot/control"],
    "sensor": ["iot/sensor"],
    "controller": ["iot/control"],
    "viewer": ["iot/login"]
}

def decrypt_data(encrypted_b64):
    try:
        data = base64.b64decode(encrypted_b64)
        iv = data[:16]
        ciphertext = data[16:-32]
        mac = data[-32:]
        expected_mac = hmac.new(HMAC_KEY, iv + ciphertext, hashlib.sha256).digest()
        if not hmac.compare_digest(mac, expected_mac):
            return "HMAC verification failed!"
        cipher = AES.new(AES_KEY, AES.MODE_CBC, iv)
        padded = cipher.decrypt(ciphertext).decode()
        pad_len = ord(padded[-1])
        return padded[:-pad_len]
    except Exception as e:
        return f"Decryption error: {str(e)}"

def load_users():
    if os.path.exists(USER_DB):
        with open(USER_DB, "r") as f:
            return json.load(f)
    return {}

def save_users(users):
    with open(USER_DB, "w") as f:
        json.dump(users, f, indent=4)

def generate_otp():
    return ''.join(random.choices(string.digits, k=6))

class LoginScreen:
    def __init__(self, master):
        self.master = master
        self.master.title("Secure MQTT Subscriber Login System")
        self.master.geometry("500x400")
        self.master.configure(bg="#f0f0f0")


        tk.Label(master, text="Username:", font=("Helvetica", 16), bg="#f0f0f0").pack(pady=5)
        self.username_entry = tk.Entry(master, width=30, font=("Helvetica", 12), bd=2, relief="solid")
        self.username_entry.pack(pady=10, ipadx=5, ipady=5)

        tk.Label(master, text="Password:", font=("Helvetica", 16), bg="#f0f0f0").pack(pady=5)
        self.password_entry = tk.Entry(master, width=30, show="*", font=("Helvetica", 12), bd=2, relief="solid")
        self.password_entry.pack(pady=10, ipadx=5, ipady=5)

        self.show_pwd = False
        self.eye_btn = tk.Button(master, text="👁", command=self.toggle_password)
        self.eye_btn.pack(pady=2)



        tk.Button(master, text="Login", width=20, font=("Helvetica", 16), bg="#4CAF50", fg="white", command=self.login, relief="solid").pack(pady=10, fill="x", padx=50)
        tk.Button(master, text="Forgot Password", width=20, font=("Helvetica", 16), bg="#f44336", fg="white", command=self.open_forgot_password, relief="solid").pack(pady=5, fill="x", padx=50)

    def toggle_password(self):     
        if self.show_pwd:
            self.password_entry.config(show="*")
            self.eye_btn.config(text="👁")
        else:
            self.password_entry.config(show="")
            self.eye_btn.config(text="🙈")
        self.show_pwd = not self.show_pwd

    def login(self):
        username = self.username_entry.get().strip()
        password = self.password_entry.get().strip()
        users = load_users()

        if time.time() < users.get(username, {}).get("lock_time", 0):
            remaining = int(users[username]["lock_time"] - time.time())
            messagebox.showerror("Account Locked", f"Try again in {remaining} seconds.")
            return

        if username in users and bcrypt.checkpw(password.encode(), users[username]["password"].encode()):
            users[username]["attempts"] = 0
            users[username]["lock_time"] = 0
            save_users(users)
            role = users[username].get("role", "sensor")
            self.master.destroy()
            root = tk.Tk()
            MQTTSubscriberApp(root, username, role)
            root.mainloop()
        else:
            if username in users:
                users[username]["attempts"] = users[username].get("attempts", 0) + 1
                if users[username]["attempts"] >= 3:
                    users[username]["lock_time"] = time.time() + LOCKOUT_DURATION
                    save_users(users)
                    messagebox.showerror("Locked", "Too many failed attempts. Locked for 5 minutes.")
                else:
                    save_users(users)
                    messagebox.showerror("Login Failed", f"Incorrect password. Attempts: {users[username]['attempts']}/3")
            else:
                messagebox.showerror("Login Failed", "Invalid username or password.")

    def open_forgot_password(self):
        self.master.destroy()
        root = tk.Tk()
        ForgotPasswordStep1(root)
        root.mainloop()

class ForgotPasswordStep1:
    def __init__(self, master):
        self.master = master
        self.master.title("Forgot Password")
        self.master.geometry("400x300")
        self.master.configure(bg="#fff0f0")

        tk.Label(master, text="Enter your username:", font=("Helvetica", 16), bg="#fff0f0").pack(pady=10)
        self.username_entry = tk.Entry(master, width=30, font=("Helvetica", 12), bd=2, relief="solid")
        self.username_entry.pack(pady=10, ipadx=5, ipady=5)

        tk.Button(master, text="Send OTP", font=("Helvetica", 16), command=self.verify_username).pack(pady=10,  fill="x", padx=50)
        tk.Button(master, text="Back", font=("Helvetica", 16), command=self.go_back).pack(pady=5, fill="x", padx=50)


    def verify_username(self):
        username = self.username_entry.get().strip()
        users = load_users()
        if username in users:
            otp = generate_otp()
            OTP_STORE[username] = {"otp": otp, "time": time.time()}
            messagebox.showinfo("OTP", f"Your OTP is: {otp}")
            self.master.destroy()
            root = tk.Tk()
            ForgotPasswordStep2(root, username)
            root.mainloop()
        else:
            messagebox.showerror("Error", "Username not found.")

    def go_back(self):
        self.master.destroy()
        root = tk.Tk()
        LoginScreen(root)
        root.mainloop()

class ForgotPasswordStep2:
    def __init__(self, master, username):
        self.master = master
        self.username = username
        self.master.title("Reset Password")
        self.master.geometry("400x350")
        self.master.configure(bg="#f9f9ff")

        tk.Label(master, text="Enter OTP:", font=("Helvetica", 12), bg="#f7f7f7").pack(pady=5)
        global otp_entry
        self.otp_entry = tk.Entry(master, show="*", font=("Helvetica", 12), bd=2, relief="solid")
        self.otp_entry.pack(pady=10, ipadx=5, ipady=5)

    

        tk.Label(master, text="New Password:", font=("Helvetica", 12), bg="#f7f7f7").pack(pady=5)
        global new_pwd_entry
        self.new_pwd_entry = tk.Entry(master, show="*", font=("Helvetica", 12), bd=2, relief="solid")
        self.new_pwd_entry.pack(pady=10, ipadx=5, ipady=5)



        tk.Label(master, text="Confirm Password:", font=("Helvetica", 12), bg="#f7f7f7").pack(pady=5)
        global confirm_pwd_entry
        self.confirm_pwd_entry = tk.Entry(master, show="*", font=("Helvetica", 12), bd=2, relief="solid")
        self.confirm_pwd_entry.pack(pady=10, ipadx=5, ipady=5)

        self.show_pwd = False
        self.eye_btn = tk.Button(master, text="👁", command=self.toggle_passwords)
        self.eye_btn.pack(pady=2)

        # Reset Password button
        tk.Button(master, text="Reset Password", font=("Helvetica", 16), bg="#4CAF50", fg="white", command=self.reset_password, relief="solid").pack(pady=15, fill="x", padx=50)
        
        # Resend otp button
        tk.Button(master, text="Resend OTP", font=("Helvetica", 16), bg="#f44336", fg="white", command=self.resend_otp, relief="solid").pack(pady=10, fill="x", padx=50)

      # Back button
        tk.Button(master, text="Back", font=("Helvetica", 16), bg="#FF9800", fg="white", command=self.go_back, relief="solid").pack(pady=15, fill="x", padx=50)

    def toggle_passwords(self):
        if self.show_pwd:
            self.new_pwd_entry.config(show="*")
            self.confirm_pwd_entry.config(show="*")
            self.eye_btn.config(text="👁")
        else:
            self.new_pwd_entry.config(show="")
            self.confirm_pwd_entry.config(show="")
            self.eye_btn.config(text="🙈")
        self.show_pwd = not self.show_pwd

    def reset_password(self):
        entered_otp = self.otp_entry.get().strip()
        new_pwd = self.new_pwd_entry.get().strip()
        confirm_pwd = self.confirm_pwd_entry.get().strip()

        otp_record = OTP_STORE.get(self.username, {})
        if not otp_record or entered_otp != otp_record.get("otp") or time.time() - otp_record["time"] > OTP_EXPIRY:
            messagebox.showerror("Error", "Invalid or expired OTP.")
            return

        if new_pwd != confirm_pwd or not new_pwd:
            messagebox.showerror("Error", "Passwords do not match or are empty.")
            return

        users = load_users()
        users[self.username]["password"] = bcrypt.hashpw(new_pwd.encode(), bcrypt.gensalt()).decode()
        save_users(users)
        del OTP_STORE[self.username]
        messagebox.showinfo("Success", "Password reset successfully.")
        self.master.destroy()
        root = tk.Tk()
        LoginScreen(root)
        root.mainloop()

    def resend_otp(self):
        otp = generate_otp()
        OTP_STORE[self.username] = {"otp": otp, "time": time.time()}
        messagebox.showinfo("New OTP", f"Your new OTP is: {otp}")

    def go_back(self):
        self.master.destroy()
        root = tk.Tk()
        LoginScreen(root)
        root.mainloop()

class MQTTSubscriberApp:
    def __init__(self, master, username, role):
        self.master = master
        self.username = username
        self.role = role
        self.master.title(f"MQTT Secure Subscriber - User: {username} (Role: {role})")
        self.master.geometry("500x400")
        self.master.configure(bg="#e6f2ff")
        self.client = None

        tk.Label(master, text="MQTT Broker:", bg="#e6f2ff", font=("Arial", 20)).pack(pady=5)
        self.broker_entry = tk.Entry(master, width=40)
        self.broker_entry.insert(0, "localhost",)
        self.broker_entry.pack(pady=10, ipadx=8, ipady=8)

        tk.Label(master, text="Select Topic:", bg="#e6f2ff", font=("Arial", 20)).pack(pady=5)
        self.topic_var = tk.StringVar()

        # Set allowed topics based on role
        allowed_topics = ROLE_TOPICS.get(role, [])
        if not allowed_topics:
            messagebox.showerror("Access Denied", f"No topics allowed for role '{role}'. Exiting.")
            self.master.destroy()
            return

        self.topic_var.set(allowed_topics[0])
        self.topic_menu = tk.OptionMenu(master, self.topic_var, *allowed_topics)
        self.topic_menu.pack(pady=5,ipadx=8, ipady=8)

        self.connect_btn = tk.Button(master, text="Connect & Subscribe",font=("Helvetica", 16),  bg="#2196F3", fg="white", width=25, command=self.connect_to_broker)
        self.connect_btn.pack(pady=10, ipadx=5, ipady=5)

        self.disconnect_btn = tk.Button(master, text="Disconnect", font=("Helvetica", 16),bg="#F44336", fg="white", width=25, command=self.disconnect, state=tk.DISABLED)
        self.disconnect_btn.pack(pady=5, ipadx=5, ipady=5)

        self.logout_btn = tk.Button(master, text="Logout", font=("Helvetica", 16),bg="#9C27B0", fg="white", width=25, command=self.logout, state=tk.DISABLED)
        self.logout_btn.pack(pady=10, ipadx=5, ipady=5)


       

    def log_message(self, topic, decrypted_msg):
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
        ip = "N/A"
        try:
            ip = socket.gethostbyname(socket.gethostname())
        except:
            pass

        users = load_users()
        role = users.get(self.username, {}).get("role", "unknown")

        with open(LOG_FILE, "a") as f:
            f.write(f"[{timestamp}] {self.username}: {role} | Action: Subscribed | Topic: {topic} | IP: {ip} | Message: {decrypted_msg}\n")


    def on_connect(self, client, userdata, flags, rc):
        if rc == 0:
            messagebox.showinfo("Connected", f"Connected to MQTT Broker successfully!")
            self.connect_btn.config(state=tk.DISABLED)
            self.disconnect_btn.config(state=tk.NORMAL)
            self.logout_btn.config(state=tk.NORMAL)
            topic = self.topic_var.get()
            # Subscribe only if topic is allowed for role
            allowed_topics = ROLE_TOPICS.get(self.role, [])
            if topic in allowed_topics:
                client.subscribe(topic)
            else:
                messagebox.showerror("Access Denied", f"You are not authorized to subscribe to {topic}.")
                client.disconnect()
        else:
            messagebox.showerror("Connection Failed", f"Failed to connect, return code {rc}")

    def on_message(self, client, userdata, msg):
        decrypted_msg = decrypt_data(msg.payload.decode())
        self.log_message(msg.topic, decrypted_msg)
        messagebox.showinfo("New Message", f"Topic: {msg.topic}\nMessage: {decrypted_msg}")

    def connect_to_broker(self):
        broker = self.broker_entry.get().strip()
        if not broker:
            messagebox.showerror("Error", "Please enter MQTT broker address.")
            return

        self.client = mqtt.Client()
        self.client.on_connect = self.on_connect
        self.client.on_message = self.on_message

        try:
            self.client.connect(broker)
            self.client.loop_start()
        except Exception as e:
            messagebox.showerror("Connection Error", str(e))

    def disconnect(self):
        if self.client:
            self.client.loop_stop()
            self.client.disconnect()
            self.connect_btn.config(state=tk.NORMAL)
            self.disconnect_btn.config(state=tk.DISABLED)
            messagebox.showinfo("Disconnected", "Disconnected from MQTT Broker.")

    def logout(self):
        if self.client:
            self.disconnect()
        self.master.destroy()
        root = tk.Tk()
        LoginScreen(root)
        root.mainloop()


if __name__ == "__main__":
    root = tk.Tk()
    LoginScreen(root)
    root.mainloop()

