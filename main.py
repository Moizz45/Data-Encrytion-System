import streamlit as st
import json
import os
from cryptography.fernet import Fernet

# === Constants ===
DATA_FILE = "users_db.json"
FERNET_KEY = b'Wwzqv2SLvnQrNS0uTWxkzDgFZAc_fYjMXbn3pP_GJ9g='
fernet = Fernet(FERNET_KEY)

# === Helper Functions ===

def load_users():
    if not os.path.exists(DATA_FILE):
        with open(DATA_FILE, "w") as f:
            json.dump({}, f)
    with open(DATA_FILE, "r") as f:
        try:
            return json.load(f)
        except json.JSONDecodeError:
            return {}

def save_users(users):
    with open(DATA_FILE, "w") as f:
        json.dump(users, f, indent=2)

def authenticate(username, password):
    users = load_users()
    return username in users and users[username]["password"] == password

def signup(username, password):
    users = load_users()
    if username in users:
        return False
    users[username] = {"password": password, "data": []}
    save_users(users)
    return True

def save_message(username, enc_text):
    users = load_users()
    users[username]["data"].append(enc_text)
    save_users(users)

# === Streamlit Setup ===
st.set_page_config(page_title="Encryption App", layout="centered")
st.title("🔐 Encryption Vault")

# Session states
if "logged_in" not in st.session_state:
    st.session_state.logged_in = False
    st.session_state.username = ""

# === Login & Signup ===
if not st.session_state.logged_in:
    login_tab, signup_tab = st.tabs(["🔑 Login", "📝 Signup"])

    with login_tab:
        username = st.text_input("Username", key="login_user")
        password = st.text_input("Password", type="password", key="login_pass")
        if st.button("Login"):
            if authenticate(username, password):
                st.session_state.logged_in = True
                st.session_state.username = username
                st.rerun()
            else:
                st.error("Invalid credentials.")

    with signup_tab:
        new_user = st.text_input("Create Username", key="signup_user")
        new_pass = st.text_input("Create Password", type="password", key="signup_pass")
        if st.button("Sign Up"):
            if signup(new_user, new_pass):
                st.success("Account created successfully.")
            else:
                st.warning("Username already exists.")

# === Main App (Post Login) ===
else:
    st.success(f"Welcome, {st.session_state.username}")
    option = st.radio("Choose Action", ["Encrypt Text", "Decrypt Text", "View Saved Messages", "Logout"])

    if option == "Encrypt Text":
        input_text = st.text_area("Enter text to encrypt")
        if st.button("Encrypt"):
            if input_text:
                encrypted = fernet.encrypt(input_text.encode()).decode()
                st.code(encrypted)
                save_message(st.session_state.username, encrypted)
            else:
                st.warning("Please enter text.")

    elif option == "Decrypt Text":
        enc_input = st.text_area("Paste encrypted text")
        key_input = st.text_input("Enter decryption password", type="password")
        if st.button("Decrypt"):
            if key_input != "1234":
                st.error("Wrong decryption password!")
            elif not enc_input:
                st.warning("Encrypted text is required.")
            else:
                try:
                    decrypted = fernet.decrypt(enc_input.encode()).decode()
                    st.code(decrypted)
                except:
                    st.error("Invalid encrypted input.")

    elif option == "View Saved Messages":
        users = load_users()
        data = users.get(st.session_state.username, {}).get("data", [])
        if data:
            st.subheader("Saved Encrypted Messages:")
            for i, msg in enumerate(data, 1):
                st.code(f"{i}. {msg}")
        else:
            st.info("No messages saved yet.")

    elif option == "Logout":
        st.session_state.logged_in = False
        st.session_state.username = ""
        st.success("Logged out successfully.")
