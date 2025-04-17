import streamlit as st
import json
import os
import time
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64

# Constants
LOCKOUT_DURATION = 60  # seconds
MAX_ATTEMPTS = 3
SALT = b'secure_salt'

# File paths
USERS_FILE = 'users.json'
DATA_FILE = 'encrypted_data.json'

# Initialize or load data
def load_json_file(filename, default):
    if os.path.exists(filename):
        with open(filename, 'r') as f:
            return json.load(f)
    return default

def save_json_file(filename, data):
    with open(filename, 'w') as f:
        json.dump(data, f)

# Load data
users = load_json_file(USERS_FILE, {})
encrypted_data = load_json_file(DATA_FILE, {})
failed_attempts = {}

# PBKDF2 hashing function
def hash_password(password):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=SALT,
        iterations=100000,
    )
    return base64.b64encode(kdf.derive(password.encode())).decode()

def is_locked_out(username):
    if username in failed_attempts:
        last_attempt = failed_attempts[username]['time']
        attempts = failed_attempts[username]['count']
        if attempts >= MAX_ATTEMPTS:
            if time.time() - last_attempt < LOCKOUT_DURATION:
                return True
            else:
                failed_attempts[username] = {'count': 0, 'time': time.time()}
    return False

def encrypt_data(text, key):
    f = Fernet(key)
    return f.encrypt(text.encode()).decode()

def decrypt_data(encrypted_text, key):
    try:
        f = Fernet(key)
        return f.decrypt(encrypted_text.encode()).decode()
    except:
        return None

# Streamlit UI
st.title("🔒 Secure Data Encryption System")

if 'logged_in' not in st.session_state:
    st.session_state.logged_in = False
if 'current_user' not in st.session_state:
    st.session_state.current_user = None

if not st.session_state.logged_in:
    menu = ["Login", "Register"]
else:
    menu = ["Home", "Store Data", "Retrieve Data", "Logout"]
choice = st.sidebar.selectbox("Navigation", menu)

def login(username, password):
    if username in users:
        if is_locked_out(username):
            st.error(f"Account locked. Try again in {LOCKOUT_DURATION} seconds.")
            return False

        hashed_password = hash_password(password)
        if users[username]['password'] == hashed_password:
            failed_attempts[username] = {'count': 0, 'time': time.time()}
            st.session_state.logged_in = True
            st.session_state.current_user = username
            return True
        else:
            if username not in failed_attempts:
                failed_attempts[username] = {'count': 0, 'time': time.time()}
            failed_attempts[username]['count'] += 1
            failed_attempts[username]['time'] = time.time()
            st.error(f"Invalid password. Attempts left: {MAX_ATTEMPTS - failed_attempts[username]['count']}")
            return False
    else:
        st.error("Username not found")
        return False

def register(username, password):
    if username in users:
        st.error("Username already exists")
        return False
    if len(username) < 3:
        st.error("Username must be at least 3 characters")
        return False
    if len(password) < 8:
        st.error("Password must be at least 8 characters")
        return False

    users[username] = {
        'password': hash_password(password),
        'key': Fernet.generate_key().decode()
    }
    save_json_file(USERS_FILE, users)
    st.success("Registration successful! Please login.")
    return True

if choice == "Login":
    st.subheader("🔑 Login")
    username = st.text_input("Username")
    password = st.text_input("Password", type="password")

    if st.button("Login"):
        if login(username, password):
            st.rerun()

elif choice == "Register":
    st.subheader("📝 Register")
    username = st.text_input("Choose Username")
    password = st.text_input("Choose Password", type="password")

    if st.button("Register"):
        if register(username, password):
            st.rerun()

elif st.session_state.logged_in:
    if choice == "Home":
        st.subheader(f"🏠 Welcome, {st.session_state.current_user}!")
        st.write("Use this app to **securely store and retrieve data** using your unique passkey.")

    elif choice == "Store Data":
        st.subheader("📂 Store Data Securely")
        user_data = st.text_area("Enter Data:")
        passkey = st.text_input("Enter Passkey:", type="password")

        if st.button("Encrypt & Save"):
            if user_data and passkey:
                user_key = users[st.session_state.current_user]['key']
                encrypted_text = encrypt_data(user_data, user_key)
                if st.session_state.current_user not in encrypted_data:
                    encrypted_data[st.session_state.current_user] = []
                encrypted_data[st.session_state.current_user].append({
                    'encrypted_text': encrypted_text,
                    'passkey': hash_password(passkey)
                })
                save_json_file(DATA_FILE, encrypted_data)
                st.success("✅ Data stored securely!")
            else:
                st.error("⚠️ Both fields are required!")

    elif choice == "Retrieve Data":
        st.subheader("🔍 Retrieve Your Data")
        passkey = st.text_input("Enter Passkey:", type="password")

        if st.button("Decrypt"):
            if passkey:
                user_key = users[st.session_state.current_user]['key']
                user_data = encrypted_data.get(st.session_state.current_user, [])
                for item in user_data:
                    if item['passkey'] == hash_password(passkey):
                        decrypted_text = decrypt_data(item['encrypted_text'], user_key)
                        if decrypted_text:
                            st.success(f"✅ Decrypted Data: {decrypted_text}")
                            break
                else:
                    st.error("❌ Incorrect passkey!")
            else:
                st.error("⚠️ Passkey is required!")

    elif choice == "Logout":
        st.session_state.logged_in = False
        st.session_state.current_user = None
        st.rerun()
