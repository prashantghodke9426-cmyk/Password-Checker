import streamlit as st
import pandas as pd
import re
import os
import pickle
import random
import string
from sklearn.linear_model import LogisticRegression

# -----------------------------
# Feature Extraction
# -----------------------------
def extract_features(password):
    length = len(password)
    has_upper = 1 if re.search(r'[A-Z]', password) else 0
    has_lower = 1 if re.search(r'[a-z]', password) else 0
    has_digit = 1 if re.search(r'[0-9]', password) else 0
    has_special = 1 if re.search(r'[@$!%*?&]', password) else 0
    return [length, has_upper, has_lower, has_digit, has_special]

# -----------------------------
# Suggestions
# -----------------------------
def generate_suggestions(password):
    suggestions = []

    if len(password) < 8:
        suggestions.append("Add at least 8 characters")
    if not re.search(r'[A-Z]', password):
        suggestions.append("Add at least one uppercase letter")
    if not re.search(r'[a-z]', password):
        suggestions.append("Add at least one lowercase letter")
    if not re.search(r'[0-9]', password):
        suggestions.append("Add at least one number")
    if not re.search(r'[@$!%*?&]', password):
        suggestions.append("Add at least one special character (@$!%*?&)")

    return suggestions

# -----------------------------
# Password Generator
# -----------------------------
def generate_password(length=12):
    characters = string.ascii_letters + string.digits + "@$!%*?&"
    password = ''.join(random.choice(characters) for _ in range(length))
    return password

# -----------------------------
# Train Model Automatically
# -----------------------------
def train_model():
    data = {
        "password": [
            "12345", "password", "hello", "abc123",
            "Pass123", "Hello123", "Pass@123",
            "Strong@2024", "Ultra@Secure99", "Admin@123"
        ],
        "strength": [0, 0, 0, 1, 1, 1, 2, 2, 2, 2]
    }

    df = pd.DataFrame(data)

    X = df["password"].apply(extract_features).tolist()
    y = df["strength"]

    model = LogisticRegression()
    model.fit(X, y)

    with open("model.pkl", "wb") as f:
        pickle.dump(model, f)

    return model

# -----------------------------
# Load or Train Model
# -----------------------------
if not os.path.exists("model.pkl"):
    model = train_model()
else:
    with open("model.pkl", "rb") as f:
        model = pickle.load(f)

# -----------------------------
# UI Setup
# -----------------------------
st.set_page_config(page_title="AI Password Checker", page_icon="🔐")

st.markdown("""
<style>
.big-font {
    font-size:25px !important;
    font-weight: bold;
}
</style>
""", unsafe_allow_html=True)

st.title("🔐 AI Password Strength Checker")
st.write("AI Powered | Animated Strength Meter | Smart Suggestions")

# -----------------------------
# Password Input
# -----------------------------
password = st.text_input("Enter your password", type="password")

# -----------------------------
# Generate Password Button
# -----------------------------
if st.button("Generate Strong Password"):
    new_password = generate_password()
    st.success(f"Generated Password: `{new_password}`")

# -----------------------------
# Check Strength
# -----------------------------
if st.button("Check Strength"):
    if password:

        features = [extract_features(password)]
        prediction = model.predict(features)[0]
        probability = model.predict_proba(features)[0]
        strength_score = round(max(probability) * 100)

        # 🎨 Animated Color Bar
        if strength_score < 40:
            color = "red"
            label = "Weak"
        elif strength_score < 75:
            color = "orange"
            label = "Medium"
        else:
            color = "green"
            label = "Strong"

        st.markdown(f"""
        <div style="background-color:#ddd; border-radius:10px;">
            <div style="
                width:{strength_score}%;
                background-color:{color};
                padding:10px;
                border-radius:10px;
                text-align:center;
                color:white;
                font-weight:bold;">
                {strength_score}% - {label}
            </div>
        </div>
        """, unsafe_allow_html=True)

        # Status Message
        if prediction == 0:
            st.error("Weak Password ❌")
        elif prediction == 1:
            st.warning("Medium Password ⚠️")
        else:
            st.success("Strong Password ✅")

        # Suggestions
        suggestions = generate_suggestions(password)
        if suggestions:
            st.subheader("Suggestions to Improve:")
            for suggestion in suggestions:
                st.write(f"🔹 {suggestion}")
        else:
            st.success("Excellent! Your password follows best practices 🎉")

    else:
        st.warning("Please enter a password.")