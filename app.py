import streamlit as st
import sqlite3
import hashlib
import datetime
import math
import re
import random
import string
import matplotlib.pyplot as plt

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
    created_at TEXT,
    is_verified INTEGER DEFAULT 0
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

add_column_if_not_exists("users", "is_verified", "INTEGER DEFAULT 0")
add_column_if_not_exists("password_history", "password_hash", "TEXT")
add_column_if_not_exists("password_history", "score", "INTEGER")
add_column_if_not_exists("password_history", "entropy", "REAL")
add_column_if_not_exists("password_history", "date", "TEXT")

# -----------------------------
# PASSWORD FUNCTIONS
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
# ADVANCED PREMIUM UI (REPLACE ONLY YOUR CSS SECTION WITH THIS)
# -----------------------------
st.markdown("""
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;700;900&family=Poppins:wght@400;600;800&display=swap" rel="stylesheet">

<style>

/* =========================
   3D PARTICLE ANIMATED BACKGROUND
========================= */
.stApp {
    font-family: 'Inter', sans-serif;
    background: radial-gradient(circle at 20% 20%, #1a1a2e, #0f3460, #000000);
    overflow-x: hidden;
}

.stApp::before {
    content: "";
    position: fixed;
    width: 200%;
    height: 200%;
    top: -50%;
    left: -50%;
    background-image: radial-gradient(white 1px, transparent 1px);
    background-size: 50px 50px;
    opacity: 0.05;
    animation: moveParticles 60s linear infinite;
    z-index: 0;
}

@keyframes moveParticles {
    from { transform: translate(0,0); }
    to { transform: translate(200px,200px); }
}

/* =========================
   LARGE BOLD TITLE
========================= */
.main-title {
    font-size: 65px;
    font-weight: 900;
    font-family: 'Poppins', sans-serif;
    text-align: center;
    color: white;
    margin-top: 20px;
    animation: fadeInDown 1s ease-in-out;
    z-index: 2;
    position: relative;
}

/* =========================
   GLASSMORPHISM CARDS
========================= */
.glass-card {
    background: rgba(255, 255, 255, 0.12);
    backdrop-filter: blur(18px);
    border-radius: 25px;
    padding: 30px;
    margin: 20px 0;
    box-shadow: 0 8px 40px rgba(0,0,0,0.4);
    animation: slideUp 0.8s ease;
    color: white;
    position: relative;
    z-index: 2;
}

/* =========================
   FLOAT EFFECT
========================= */
@keyframes float {
    0% { transform: translatey(0px); }
    50% { transform: translatey(-12px); }
    100% { transform: translatey(0px); }
}

.glass-card:hover {
    animation: float 3s ease-in-out infinite;
}

/* =========================
   NEON BUTTONS
========================= */
div.stButton > button {
    background: transparent;
    color: #00f5ff;
    border: 2px solid #00f5ff;
    border-radius: 30px;
    padding: 10px 25px;
    font-weight: 600;
    transition: 0.3s ease;
}

div.stButton > button:hover {
    background: #00f5ff;
    color: black;
    box-shadow: 0 0 20px #00f5ff,
                0 0 40px #00f5ff,
                0 0 60px #00f5ff;
}

/* =========================
   PREMIUM LOCK OVERLAY
========================= */
.premium-lock {
    position: relative;
}

.premium-lock::after {
    content: "🔒 Premium Feature";
    position: absolute;
    top: 10px;
    right: 15px;
    background: linear-gradient(45deg, gold, orange);
    color: black;
    padding: 5px 15px;
    border-radius: 20px;
    font-size: 12px;
    font-weight: 700;
}

/* =========================
   ADMIN DASHBOARD GLASS
========================= */
.admin-glass {
    background: rgba(0, 255, 255, 0.08);
    backdrop-filter: blur(20px);
    border: 1px solid rgba(0,255,255,0.3);
    border-radius: 25px;
    padding: 40px;
    margin-top: 30px;
    box-shadow: 0 0 40px rgba(0,255,255,0.2);
    color: white;
    animation: fadeInDown 1s ease;
}

/* =========================
   ANIMATIONS
========================= */
@keyframes fadeInDown {
    from { opacity: 0; transform: translateY(-40px); }
    to { opacity: 1; transform: translateY(0); }
}

@keyframes slideUp {
    from { opacity: 0; transform: translateY(50px); }
    to { opacity: 1; transform: translateY(0); }
}

</style>
""", unsafe_allow_html=True)

st.markdown('<div class="main-title">🔐 Elite SaaS Password Checker</div>', unsafe_allow_html=True)
# -----------------------------
# MENU (MUST BE BEFORE USING choice)
# -----------------------------
menu = ["Login", "Register"]
choice = st.sidebar.selectbox("Menu", menu)

# -----------------------------
# PREMIUM UI BOX (Optional Visual Only)
# -----------------------------
st.markdown("""
<div class="glass-card premium-lock">
<h3>🚀 Premium Analytics Dashboard</h3>
<p>Upgrade to unlock AI insights, breach monitoring & enterprise reporting.</p>
</div>
""", unsafe_allow_html=True)

# -----------------------------
# ADMIN GLASS DASHBOARD (UI ONLY)
# -----------------------------
st.markdown("""
<div class="admin-glass">
<h3>👑 Admin Control Center</h3>
<p>Advanced monitoring • User management • Security insights</p>
</div>
""", unsafe_allow_html=True)

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
            st.info("Please verify your email after login.")
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
            st.session_state.is_verified = user[6]
            st.success("Logged In Successfully")
        else:
            st.error("Invalid Credentials")

# -----------------------------
# DASHBOARD
# -----------------------------
if st.session_state.logged_in:

    st.sidebar.success(f"Welcome {st.session_state.username}")

    page = st.sidebar.selectbox("Dashboard", 
        ["Password Checker", "Password Generator", "History", "Analytics Dashboard", "Email Verification", "Logout"])

    # -----------------------------
    # EMAIL VERIFICATION
    # -----------------------------
    if page == "Email Verification":
        st.subheader("Verify Your Email")

        if st.session_state.is_verified:
            st.success("Your email is already verified ✅")
        else:
            if "otp" not in st.session_state:
                st.session_state.otp = str(random.randint(100000, 999999))

            st.info(f"Your Verification OTP (simulation): {st.session_state.otp}")

            entered = st.text_input("Enter OTP")

            if st.button("Verify"):
                if entered == st.session_state.otp:
                    c.execute("UPDATE users SET is_verified=1 WHERE id=?",
                              (st.session_state.user_id,))
                    conn.commit()
                    st.session_state.is_verified = 1
                    st.success("Email Verified Successfully 🎉")
                else:
                    st.error("Invalid OTP")

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

            st.progress(score / 100)
            st.write(f"Strength Score: {score}%")
            st.write(f"Entropy: {entropy}")

            if suggestions:
                st.warning("Suggestions:")
                for s in suggestions:
                    st.write("•", s)
            else:
                st.success("Strong Password!")

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

    # -----------------------------
    # HISTORY
    # -----------------------------
    if page == "History":
        st.subheader("Password History")

        c.execute("""
        SELECT score, entropy, date
        FROM password_history
        WHERE user_id=?
        ORDER BY id ASC
        """, (st.session_state.user_id,))

        data = c.fetchall()

        if data:
            for row in data:
                st.write(f"Score: {row[0]}% | Entropy: {row[1]} | Date: {row[2]}")
        else:
            st.info("No history found.")

    # -----------------------------
    # ANALYTICS DASHBOARD
    # -----------------------------
    if page == "Analytics Dashboard":
        st.subheader("📈 Password Strength Analytics")

        c.execute("""
        SELECT score, date FROM password_history
        WHERE user_id=?
        ORDER BY id ASC
        """, (st.session_state.user_id,))

        records = c.fetchall()

        if records:
            scores = [r[0] for r in records]
            dates = [r[1] for r in records]

            plt.figure()
            plt.plot(dates, scores)
            plt.xticks(rotation=45)
            plt.xlabel("Date")
            plt.ylabel("Score")
            plt.title("Password Strength Trend")
            st.pyplot(plt)
        else:
            st.info("No analytics data available.")

    # -----------------------------
    # LOGOUT
    # -----------------------------
    if page == "Logout":
        st.session_state.logged_in = False
        st.success("Logged Out Successfully")