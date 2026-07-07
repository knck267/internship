import streamlit as st
import sqlite3
import bcrypt
import re
import os
import datetime

st.set_page_config(page_title="Secure Login", page_icon="🔐")

# ---- database setup ----
DB_FILE = "users.db"

def init_db():
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            created_at TEXT NOT NULL
        )
    ''')
    conn.commit()
    conn.close()

def get_connection():
    return sqlite3.connect(DB_FILE)

# ---- password hashing ----
def hash_password(password):
    salt = bcrypt.gensalt()
    hashed = bcrypt.hashpw(password.encode('utf-8'), salt)
    return hashed.decode('utf-8')

def check_password(password, hashed):
    return bcrypt.checkpw(password.encode('utf-8'), hashed.encode('utf-8'))

# ---- input validation ----
def validate_username(username):
    if len(username) < 3:
        return False, "username must be at least 3 characters"
    if len(username) > 20:
        return False, "username too long, max 20 characters"
    # only allow letters numbers and underscore
    if not re.match(r'^[a-zA-Z0-9_]+$', username):
        return False, "username can only have letters, numbers, and underscore"
    return True, ""

def validate_email(email):
    if not re.match(r'^[^@]+@[^@]+\.[^@]+$', email):
        return False, "invalid email address"
    return True, ""

def validate_password(password):
    if len(password) < 8:
        return False, "password must be at least 8 characters"
    if not re.search(r'[A-Z]', password):
        return False, "password needs at least one uppercase letter"
    if not re.search(r'[0-9]', password):
        return False, "password needs at least one number"
    return True, ""

# ---- user functions ----
def register_user(username, email, password):
    try:
        conn = get_connection()
        c = conn.cursor()
        # using parameterized queries to prevent sql injection
        hashed = hash_password(password)
        now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        c.execute(
            "INSERT INTO users (username, email, password_hash, created_at) VALUES (?, ?, ?, ?)",
            (username.lower(), email.lower(), hashed, now)
        )
        conn.commit()
        conn.close()
        return True, "account created successfully"
    except sqlite3.IntegrityError:
        return False, "username or email already exists"
    except Exception as e:
        return False, str(e)

def login_user(username, password):
    try:
        conn = get_connection()
        c = conn.cursor()
        # parameterized query - safe from sql injection
        c.execute(
            "SELECT username, email, password_hash, created_at FROM users WHERE username = ?",
            (username.lower(),)
        )
        row = c.fetchone()
        conn.close()
        if row is None:
            return False, None
        db_username, db_email, db_hash, created_at = row
        if check_password(password, db_hash):
            return True, {"username": db_username, "email": db_email, "created_at": created_at}
        return False, None
    except Exception as e:
        return False, None

def user_exists(username):
    conn = get_connection()
    c = conn.cursor()
    c.execute("SELECT 1 FROM users WHERE username = ?", (username.lower(),))
    result = c.fetchone()
    conn.close()
    return result is not None

# init db on startup
init_db()

# ---- session state setup ----
if "logged_in" not in st.session_state:
    st.session_state.logged_in = False
if "user" not in st.session_state:
    st.session_state.user = None
if "page" not in st.session_state:
    st.session_state.page = "login"


# ======================================================
# pages
# ======================================================

def show_login():
    st.title("🔐 Login")
    st.write("welcome back, enter your details below")
    st.write("---")

    username = st.text_input("username")
    password = st.text_input("password", type="password")

    if st.button("login"):
        if not username or not password:
            st.error("please fill in all fields")
        else:
            success, user_data = login_user(username, password)
            if success:
                st.session_state.logged_in = True
                st.session_state.user = user_data
                st.session_state.page = "dashboard"
                st.rerun()
            else:
                st.error("wrong username or password")

    st.write("")
    st.write("don't have an account?")
    if st.button("go to register"):
        st.session_state.page = "register"
        st.rerun()


def show_register():
    st.title("📝 Register")
    st.write("create a new account")
    st.write("---")

    username = st.text_input("choose a username")
    email = st.text_input("email address")
    password = st.text_input("choose a password", type="password")
    confirm_password = st.text_input("confirm password", type="password")

    st.caption("password must be at least 8 characters, include a number and uppercase letter")

    if st.button("create account"):
        # basic checks
        if not username or not email or not password or not confirm_password:
            st.error("please fill in all fields")
        elif password != confirm_password:
            st.error("passwords do not match")
        else:
            # validate each field
            ok, msg = validate_username(username)
            if not ok:
                st.error(msg)
            else:
                ok, msg = validate_email(email)
                if not ok:
                    st.error(msg)
                else:
                    ok, msg = validate_password(password)
                    if not ok:
                        st.error(msg)
                    else:
                        success, result_msg = register_user(username, email, password)
                        if success:
                            st.success("account created! you can now login")
                            st.session_state.page = "login"
                            st.rerun()
                        else:
                            st.error(result_msg)

    st.write("")
    st.write("already have an account?")
    if st.button("go to login"):
        st.session_state.page = "login"
        st.rerun()


def show_dashboard():
    user = st.session_state.user

    st.title(f"👋 Welcome, {user['username']}!")
    st.write("you are now logged in")
    st.write("---")

    st.subheader("your account info")
    st.write(f"username: {user['username']}")
    st.write(f"email: {user['email']}")
    st.write(f"account created: {user['created_at']}")

    st.write("---")
    st.subheader("security info")
    st.write("- your password is stored as a bcrypt hash")
    st.write("- bcrypt uses salt so even same passwords have different hashes")
    st.write("- sql injection is prevented using parameterized queries")
    st.write("- input is validated before anything is saved to database")

    st.write("---")
    if st.button("logout"):
        st.session_state.logged_in = False
        st.session_state.user = None
        st.session_state.page = "login"
        st.rerun()


# ---- router ----
if st.session_state.logged_in:
    show_dashboard()
else:
    if st.session_state.page == "register":
        show_register()
    else:
        show_login()
