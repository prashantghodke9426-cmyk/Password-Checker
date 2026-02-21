import streamlit as st
import re
import math
import random
import string
import matplotlib.pyplot as plt
import pandas as pd
import sqlite3
import bcrypt
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
    subscription TEXT DEFAULT 'Free'
)
""")

c.execute("""
CREATE TABLE IF NOT EXISTS password_history (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    password TEXT,
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

# ---------------------------------------------------
# PASSWORD FUNCTIONS (UNCHANGED)
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
    upper = random.choice(string.ascii_uppercase)
    lower = random.choice(string.ascii_lowercase)
    digit = random.choice(string.digits)
    special = random.choice("@$!%*?&")
    remaining = ''.join(random.choice(
        string.ascii_letters + string.digits + "@$!%*?&"
    ) for _ in range(length - 4))
    password = list(upper + lower + digit + special + remaining)
    random.shuffle(password)
    return ''.join(password)

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

# ---------------------------------------------------
# AUTH SYSTEM
# ---------------------------------------------------
def register(username, password):
    hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt())
    try:
        c.execute("INSERT INTO users (username, password) VALUES (?,?)",
                  (username, hashed))
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

# ---------------------------------------------------
# LOGIN / REGISTER UI
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
            user = login(username, password)
            if user:
                st.session_state.logged_in = True
                st.session_state.user_id = user[0]
                st.session_state.subscription = user[3]
                st.success("Login successful!")
                st.rerun()
            else:
                st.error("Invalid credentials")

# ---------------------------------------------------
# MAIN APP (AFTER LOGIN)
# ---------------------------------------------------
else:

    st.title("🔐 AI Security Dashboard")
    st.write(f"Subscription Plan: **{st.session_state.subscription}**")

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

        # Save to history
        c.execute("""
        INSERT INTO password_history (user_id, password, score, entropy, date)
        VALUES (?,?,?,?,?)
        """, (st.session_state.user_id,
              password, score, entropy,
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
    # PASSWORD HISTORY DASHBOARD
    # ---------------------------------------------------
    st.subheader("Password History")

    c.execute("""
    SELECT password, score, entropy, date
    FROM password_history
    WHERE user_id=?
    ORDER BY id DESC
    """, (st.session_state.user_id,))
    data = c.fetchall()

    if data:
        df = pd.DataFrame(data, columns=["Password", "Score", "Entropy", "Date"])
        st.dataframe(df)

        fig = plt.figure()
        plt.plot(df["Score"])
        plt.title("Score Trend")
        st.pyplot(fig)
    else:
        st.info("No history yet.")