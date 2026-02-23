import streamlit as st
import sqlite3
import hashlib
import datetime
import math
import re
import random
import string

# -----------------------------
# DATABASE CONNECTION
# -----------------------------
conn = sqlite3.connect("database.db", check_same_thread=False)
c = conn.cursor()

# -----------------------------
# SAFE TABLE CREATION
# -----------------------------
c.execute("""
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE,
    email TEXT UNIQUE,
    password TEXT,
    role TEXT DEFAULT 'user',
    subscription TEXT DEFAULT 'free',
    created_at TEXT
)
""")

c.execute("""
CREATE TABLE IF NOT EXISTS password_history (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    password_hash TEXT,
    score INTEGER,
    entropy REAL,
    date TEXT
)
""")

conn.commit()

# -----------------------------
# SAFE COLUMN MIGRATION
# -----------------------------
def add_column_if_not_exists(table, column, definition):
    c.execute(f"PRAGMA table_info({table})")
    columns = [col[1] for col in c.fetchall()]
    if column not in columns:
        c.execute(f"ALTER TABLE {table} ADD COLUMN {column} {definition}")
        conn.commit()

add_column_if_not_exists("password_history", "password_hash", "TEXT")
add_column_if_not_exists("password_history", "score", "INTEGER")
add_column_if_not_exists("password_history", "entropy", "REAL")
add_column_if_not_exists("password_history", "date", "TEXT")

# -----------------------------
# PASSWORD UTIL FUNCTIONS
# -----------------------------
def calculate_entropy(password):
    pool = 0
    if re.search(r"[a-z]", password): pool += 26
    if re.search(r"[A-Z]", password): pool += 26
    if re.search(r"[0-9]", password): pool += 10
    if re.search(r"[!@#$%^&*(),.?\":{}|<>]", password): pool += 32
    if pool == 0:
        return 0
    entropy = len(password) * math.log2(pool)
    return round(entropy, 2)

def password_score(password):
    score = 0
    if len(password) >= 8: score += 20
    if re.search(r"[a-z]", password): score += 20
    if re.search(r"[A-Z]", password): score += 20
    if re.search(r"[0-9]", password): score += 20
    if re.search(r"[!@#$%^&*(),.?\":{}|<>]", password): score += 20
    return score

def password_suggestions(password):
    suggestions = []
    if len(password) < 8:
        suggestions.append("Increase length to at least 8 characters.")
    if not re.search(r"[a-z]", password):
        suggestions.append("Add lowercase letters.")
    if not re.search(r"[A-Z]", password):
        suggestions.append("Add uppercase letters.")
    if not re.search(r"[0-9]", password):
        suggestions.append("Add numbers.")
    if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
        suggestions.append("Add special characters.")
    return suggestions

def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

def generate_password(length=12):
    characters = string.ascii_letters + string.digits + "!@#$%^&*()"
    return ''.join(random.choice(characters) for _ in range(length))

# -----------------------------
# SESSION INIT
# -----------------------------
if "logged_in" not in st.session_state:
    st.session_state.logged_in = False

# -----------------------------
# UI STYLE
# -----------------------------
st.set_page_config(page_title="Elite Password Checker", page_icon="🔐", layout="wide")

st.markdown("""
<style>
.big-title {font-size:40px; font-weight:bold; text-align:center;}
.weak {color:red;}
.medium {color:orange;}
.strong {color:green;}
</style>
""", unsafe_allow_html=True)

st.markdown("<div class='big-title'>🔐 Elite SaaS Password Checker</div>", unsafe_allow_html=True)

menu = ["Login", "Register"]
choice = st.sidebar.selectbox("Menu", menu)

# -----------------------------
# REGISTER
# -----------------------------
if choice == "Register":
    st.subheader("Create Account")

    username = st.text_input("Username")
    email = st.text_input("Email")
    password = st.text_input("Password", type="password")

    if st.button("Register"):
        hashed = hash_password(password)
        try:
            c.execute("""
            INSERT INTO users (username, email, password, created_at)
            VALUES (?, ?, ?, ?)
            """, (username, email, hashed, str(datetime.datetime.now())))
            conn.commit()
            st.success("Account Created Successfully")
        except:
            st.error("Username or Email already exists")

# -----------------------------
# LOGIN
# -----------------------------
if choice == "Login":
    st.subheader("Login")

    username = st.text_input("Username")
    password = st.text_input("Password", type="password")

    if st.button("Login"):
        hashed = hash_password(password)
        c.execute("SELECT * FROM users WHERE username=? AND password=?", (username, hashed))
        user = c.fetchone()

        if user:
            st.session_state.logged_in = True
            st.session_state.user_id = user[0]
            st.session_state.username = user[1]
            st.session_state.role = user[4] if len(user) > 4 else "user"
            st.success("Logged In Successfully")
        else:
            st.error("Invalid Credentials")

# -----------------------------
# DASHBOARD
# -----------------------------
if st.session_state.logged_in:

    st.sidebar.success(f"Welcome {st.session_state.username}")
    page = st.sidebar.selectbox("Dashboard", ["Password Checker", "History", "Password Generator", "Logout"])

    # -----------------------------
    # PASSWORD CHECKER
    # -----------------------------
    if page == "Password Checker":
        st.subheader("Check Password Strength")

        password = st.text_input("Enter Password", type="password")

        if password:
            score = password_score(password)
            entropy = calculate_entropy(password)
            suggestions = password_suggestions(password)

            # Progress bar
            st.progress(score / 100)
            st.write(f"### Strength Score: {score}%")
            st.write(f"Entropy: {entropy}")

            # Strength label
            if score < 40:
                st.markdown("<h4 class='weak'>Weak Password</h4>", unsafe_allow_html=True)
            elif score < 80:
                st.markdown("<h4 class='medium'>Moderate Password</h4>", unsafe_allow_html=True)
            else:
                st.markdown("<h4 class='strong'>Strong / Elite Password</h4>", unsafe_allow_html=True)

            # Suggestions
            if suggestions:
                st.warning("Suggestions to improve:")
                for s in suggestions:
                    st.write("•", s)
            else:
                st.success("Excellent password! No improvements needed.")

            # Save history
            hashed = hash_password(password)
            c.execute("""
            INSERT INTO password_history (user_id, password_hash, score, entropy, date)
            VALUES (?, ?, ?, ?, ?)
            """, (st.session_state.user_id, hashed, score, entropy, str(datetime.datetime.now())))
            conn.commit()

    # -----------------------------
    # PASSWORD GENERATOR
    # -----------------------------
    if page == "Password Generator":
        st.subheader("Generate Secure Password")

        length = st.slider("Select Length", 8, 24, 12)

        if st.button("Generate"):
            new_pass = generate_password(length)
            st.code(new_pass)
            st.success("Password Generated Successfully!")

    # -----------------------------
    # HISTORY
    # -----------------------------
    if page == "History":
        st.subheader("Password History")

        c.execute("""
        SELECT password_hash, score, entropy, date
        FROM password_history
        WHERE user_id=?
        ORDER BY id DESC
        """, (st.session_state.user_id,))

        data = c.fetchall()

        if data:
            for row in data:
                st.write(f"Hash: {row[0][:12]}...")
                st.write(f"Score: {row[1]}%")
                st.write(f"Entropy: {row[2]}")
                st.write(f"Date: {row[3]}")
                st.markdown("---")
        else:
            st.info("No history found.")

    # -----------------------------
    # LOGOUT
    # -----------------------------
    if page == "Logout":
        st.session_state.logged_in = False
        st.success("Logged Out Successfully")