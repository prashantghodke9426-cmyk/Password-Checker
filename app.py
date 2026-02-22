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
import stripe
from datetime import datetime, timedelta

# ---------------- STRIPE CONFIG ----------------
stripe.api_key = "YOUR_STRIPE_SECRET_KEY"  # 🔥 PUT YOUR TEST SECRET KEY HERE
DOMAIN_URL = "http://localhost:8501"

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
    password_hash TEXT,
    score INTEGER,
    entropy REAL,
    date TEXT
)
""")

conn.commit()

# ---------------- AUTO MIGRATION ----------------
c.execute("PRAGMA table_info(users)")
columns = [col[1] for col in c.fetchall()]

if "role" not in columns:
    c.execute("ALTER TABLE users ADD COLUMN role TEXT DEFAULT 'User'")
    conn.commit()

if "api_key" not in columns:
    c.execute("ALTER TABLE users ADD COLUMN api_key TEXT")
    conn.commit()

if "failed_attempts" not in columns:
    c.execute("ALTER TABLE users ADD COLUMN failed_attempts INTEGER DEFAULT 0")
    conn.commit()

if "lock_until" not in columns:
    c.execute("ALTER TABLE users ADD COLUMN lock_until TEXT")
    conn.commit()

# ---------------------------------------------------
# PAGE CONFIG
# ---------------------------------------------------
st.set_page_config(page_title="AI Security SaaS", page_icon="🔐")

# ---------------------------------------------------
# SESSION STATE
# ---------------------------------------------------
if "logged_in" not in st.session_state:
    st.session_state.logged_in = False

# ---------------------------------------------------
# PASSWORD LOGIC
# ---------------------------------------------------
def calculate_entropy(password):
    pool = 0
    if re.search(r'[a-z]', password): pool += 26
    if re.search(r'[A-Z]', password): pool += 26
    if re.search(r'[0-9]', password): pool += 10
    if re.search(r'[@$!%*?&]', password): pool += 7
    if pool == 0: return 0
    return round(len(password) * math.log2(pool), 2)

def password_score(password):
    score = 0
    if len(password) >= 8: score += 20
    if len(password) >= 12: score += 10
    if re.search(r'[A-Z]', password): score += 20
    if re.search(r'[a-z]', password): score += 20
    if re.search(r'[0-9]', password): score += 15
    if re.search(r'[@$!%*?&]', password): score += 15
    return min(score, 100)

def hash_password_history(password):
    return hashlib.sha256(password.encode()).hexdigest()

def mask_password(hash_value):
    return hash_value[:6] + "******" + hash_value[-6:]

# ---------------------------------------------------
# AUTH SYSTEM
# ---------------------------------------------------
def register(username, password):
    hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt())
    api_key = str(uuid.uuid4())
    role = "Admin" if get_user_count() == 0 else "User"
    try:
        c.execute("""
            INSERT INTO users 
            (username, password, role, api_key, failed_attempts)
            VALUES (?,?,?,?,0)
        """, (username, hashed, role, api_key))
        conn.commit()
        return True
    except:
        return False

def login(username, password):
    c.execute("SELECT * FROM users WHERE username=?", (username,))
    user = c.fetchone()
    if not user:
        return None, "Invalid credentials"

    failed_attempts = user[6]
    lock_until = user[7]

    if lock_until:
        lock_time = datetime.strptime(lock_until, "%Y-%m-%d %H:%M:%S")
        if datetime.now() < lock_time:
            return None, "Account locked. Try later."

    if bcrypt.checkpw(password.encode(), user[2]):
        c.execute("UPDATE users SET failed_attempts=0, lock_until=NULL WHERE id=?", (user[0],))
        conn.commit()
        return user, None
    else:
        failed_attempts += 1
        if failed_attempts >= 5:
            lock_time = datetime.now() + timedelta(minutes=10)
            c.execute("UPDATE users SET failed_attempts=?, lock_until=? WHERE id=?",
                      (failed_attempts, lock_time.strftime("%Y-%m-%d %H:%M:%S"), user[0]))
        else:
            c.execute("UPDATE users SET failed_attempts=? WHERE id=?",
                      (failed_attempts, user[0]))
        conn.commit()
        return None, "Invalid credentials"

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
                st.success("Account created!")

    if menu == "Login":
        if st.button("Login"):
            user, error = login(username, password)
            if user:
                st.session_state.logged_in = True
                st.session_state.user_id = user[0]
                st.session_state.subscription = user[3]
                st.session_state.role = user[4]
                st.session_state.api_key = user[5]
                st.rerun()
            else:
                st.error(error)

# ---------------------------------------------------
# MAIN DASHBOARD
# ---------------------------------------------------
else:

    st.title("🔐 AI Security Dashboard")

    st.write(f"Subscription: **{st.session_state.subscription}**")
    st.write(f"API Key: `{st.session_state.api_key}`")

    # ---------------- STRIPE PAYMENT ----------------
    if st.button("Upgrade to Pro (Stripe ₹299)"):
        checkout_session = stripe.checkout.Session.create(
            payment_method_types=["card"],
            line_items=[{
                "price_data": {
                    "currency": "inr",
                    "product_data": {"name": "Pro Subscription"},
                    "unit_amount": 29900,
                },
                "quantity": 1,
            }],
            mode="payment",
            success_url=DOMAIN_URL + "?success=true",
            cancel_url=DOMAIN_URL + "?canceled=true",
        )
        st.markdown(f"[Click here to Pay]({checkout_session.url})")

    query_params = st.query_params
    if "success" in query_params:
        c.execute("UPDATE users SET subscription='Pro' WHERE id=?",
                  (st.session_state.user_id,))
        conn.commit()
        st.success("Payment successful. Upgraded to Pro!")
        st.session_state.subscription = "Pro"

    if st.button("Logout"):
        st.session_state.logged_in = False
        st.rerun()

    st.divider()

    password = st.text_input("Analyze Password", type="password")

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
              password_hash,
              score,
              entropy,
              datetime.now().strftime("%Y-%m-%d %H:%M:%S")))
        conn.commit()

    # History
    st.subheader("Password History")

    c.execute("""
    SELECT password_hash, score, entropy, date
    FROM password_history
    WHERE user_id=?
    ORDER BY id DESC
    """, (st.session_state.user_id,))
    data = c.fetchall()

    if data:
        df = pd.DataFrame(
            [[mask_password(r[0]), r[1], r[2], r[3]] for r in data],
            columns=["Password", "Score", "Entropy", "Date"]
        )
        st.dataframe(df)

        fig = plt.figure()
        plt.plot(df["Score"])
        st.pyplot(fig)

    # Admin
    if st.session_state.role == "Admin":
        st.subheader("Admin Dashboard")
        c.execute("SELECT COUNT(*) FROM users")
        st.write("Total Users:", c.fetchone()[0])