import streamlit as st
import re
import math
import random
import string
import matplotlib.pyplot as plt
import pandas as pd
import sqlite3
import bcrypt
import hashlib
import uuid
from datetime import datetime

# ---------------------------------------------------
# DATABASE SETUP
# ---------------------------------------------------
conn = sqlite3.connect("security_app.db", check_same_thread=False)
c = conn.cursor()

c.execute("""
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE,
    password TEXT,
    subscription TEXT DEFAULT 'Free',
    role TEXT DEFAULT 'User',
    api_key TEXT
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

# ---------------------------------------------------
# PAGE CONFIG
# ---------------------------------------------------
st.set_page_config(page_title="AI Security SaaS", page_icon="🔐", layout="centered")

# ---------------------------------------------------
# SESSION STATE
# ---------------------------------------------------
if "logged_in" not in st.session_state:
    st.session_state.logged_in = False
if "user_id" not in st.session_state:
    st.session_state.user_id = None
if "subscription" not in st.session_state:
    st.session_state.subscription = "Free"
if "failed_attempts" not in st.session_state:
    st.session_state.failed_attempts = 0

# ---------------------------------------------------
# PASSWORD FUNCTIONS
# ---------------------------------------------------
def calculate_entropy(password):
    pool = 0
    if re.search(r'[a-z]', password):
        pool += 26
    if re.search(r'[A-Z]', password):
        pool += 26
    if re.search(r'[0-9]', password):
        pool += 10
    if re.search(r'[@$!%*?&]', password):
        pool += 7
    if pool == 0:
        return 0
    return round(len(password) * math.log2(pool), 2)

def password_score(password):
    score = 0
    if len(password) >= 8:
        score += 20
    if len(password) >= 12:
        score += 10
    if re.search(r'[A-Z]', password):
        score += 20
    if re.search(r'[a-z]', password):
        score += 20
    if re.search(r'[0-9]', password):
        score += 15
    if re.search(r'[@$!%*?&]', password):
        score += 15
    return min(score, 100)

def generate_password(length=12):
    chars = string.ascii_letters + string.digits + "@$!%*?&"
    return ''.join(random.choice(chars) for _ in range(length))

def generate_suggestions(password):
    suggestions = []
    if len(password) < 8:
        suggestions.append("Increase password length (minimum 8)")
    if not re.search(r'[A-Z]', password):
        suggestions.append("Add uppercase letter")
    if not re.search(r'[a-z]', password):
        suggestions.append("Add lowercase letter")
    if not re.search(r'[0-9]', password):
        suggestions.append("Add number")
    if not re.search(r'[@$!%*?&]', password):
        suggestions.append("Add special character")
    return suggestions

def mask_password(password):
    if len(password) <= 4:
        return "*" * len(password)
    return password[:2] + "*"*(len(password)-4) + password[-2:]

def hash_password_history(password):
    return hashlib.sha256(password.encode()).hexdigest()

# ---------------------------------------------------
# AUTH SYSTEM
# ---------------------------------------------------
def register(username, password):
    hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt())
    api_key = str(uuid.uuid4())
    role = "Admin" if get_user_count() == 0 else "User"

    try:
        c.execute("INSERT INTO users (username, password, role, api_key) VALUES (?,?,?,?)",
                  (username, hashed, role, api_key))
        conn.commit()
        return True
    except:
        return False

def login(username, password):
    c.execute("SELECT * FROM users WHERE username=?", (username,))
    user = c.fetchone()
    if user and bcrypt.checkpw(password.encode(), user[2]):
        return user
    return None

def get_user_count():
    c.execute("SELECT COUNT(*) FROM users")
    return c.fetchone()[0]

# ---------------------------------------------------
# LOGIN / REGISTER
# ---------------------------------------------------
if not st.session_state.logged_in:

    st.title("🔐 AI Security SaaS")

    menu = st.radio("Select Option", ["Login", "Register"])
    username = st.text_input("Username")
    password = st.text_input("Password", type="password")

    if menu == "Register":
        if st.button("Create Account"):
            if register(username, password):
                st.success("Account created successfully!")
            else:
                st.error("Username already exists.")

    if menu == "Login":
        if st.button("Login"):

            if st.session_state.failed_attempts >= 5:
                st.error("Too many failed attempts. Try later.")
            else:
                user = login(username, password)
                if user:
                    st.session_state.logged_in = True
                    st.session_state.user_id = user[0]
                    st.session_state.subscription = user[3]
                    st.session_state.role = user[4]
                    st.session_state.api_key = user[5]
                    st.session_state.failed_attempts = 0
                    st.success("Login successful!")
                    st.rerun()
                else:
                    st.session_state.failed_attempts += 1
                    st.error("Invalid credentials")

# ---------------------------------------------------
# MAIN DASHBOARD
# ---------------------------------------------------
else:

    st.title("🔐 AI Security Dashboard")
    st.write(f"Subscription Plan: **{st.session_state.subscription}**")
    st.write(f"API Key: `{st.session_state.api_key}`")

    if st.button("Upgrade to Pro (Demo)"):
        c.execute("UPDATE users SET subscription='Pro' WHERE id=?",
                  (st.session_state.user_id,))
        conn.commit()
        st.session_state.subscription = "Pro"
        st.success("Upgraded to Pro!")

    if st.button("Logout"):
        st.session_state.logged_in = False
        st.rerun()

    st.divider()

    password = st.text_input("Enter Password to Analyze", type="password")

    if password:
        entropy = calculate_entropy(password)
        score = password_score(password)

        st.write(f"Score: {score}%")
        st.write(f"Entropy: {entropy} bits")

        password_hash = hash_password_history(password)

        c.execute("""
        INSERT INTO password_history (user_id, password_hash, score, entropy, date)
        VALUES (?,?,?,?,?)
        """, (st.session_state.user_id,
              password_hash, score, entropy,
              datetime.now().strftime("%Y-%m-%d %H:%M:%S")))
        conn.commit()

        suggestions = generate_suggestions(password)
        if suggestions:
            st.write("Suggestions:")
            for s in suggestions:
                st.write("-", s)
        else:
            st.success("Strong Password")

    # ---------------------------------------------------
    # PASSWORD HISTORY
    # ---------------------------------------------------
    st.subheader("Password History")

    c.execute("""
    SELECT password_hash, score, entropy, date
    FROM password_history
    WHERE user_id=?
    ORDER BY id DESC
    """, (st.session_state.user_id,))
    data = c.fetchall()

    if data:
        display_data = []
        for row in data:
            masked = mask_password(row[0])
            display_data.append([masked, row[1], row[2], row[3]])

        df = pd.DataFrame(display_data, columns=["Password", "Score", "Entropy", "Date"])
        st.dataframe(df)

        fig = plt.figure()
        plt.plot(df["Score"])
        plt.title("Score Trend")
        st.pyplot(fig)

        # SaaS Metrics
        avg_score = df["Score"].mean()
        weak_percent = (df["Score"] < 50).mean() * 100
        strong_percent = (df["Score"] >= 80).mean() * 100

        st.write(f"Average Score: {round(avg_score,2)}")
        st.write(f"Weak Password %: {round(weak_percent,2)}%")
        st.write(f"Strong Password %: {round(strong_percent,2)}%")

    else:
        st.info("No history yet.")

    # ---------------------------------------------------
    # ADMIN PANEL
    # ---------------------------------------------------
    if st.session_state.role == "Admin":
        st.divider()
        st.subheader("Admin Dashboard")

        total_users = get_user_count()

        c.execute("SELECT COUNT(*) FROM password_history")
        total_passwords = c.fetchone()[0]

        c.execute("SELECT COUNT(*) FROM users WHERE subscription='Pro'")
        pro_users = c.fetchone()[0]

        revenue = pro_users * 299

        st.write(f"Total Users: {total_users}")
        st.write(f"Total Passwords Analyzed: {total_passwords}")
        st.write(f"Pro Users: {pro_users}")
        st.write(f"Estimated Revenue: ₹{revenue}")