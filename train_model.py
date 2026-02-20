import pandas as pd
import re
from sklearn.model_selection import train_test_split
from sklearn.linear_model import LogisticRegression
import pickle

# Feature extractor
def extract_features(password):
    length = len(password)
    has_upper = 1 if re.search(r'[A-Z]', password) else 0
    has_lower = 1 if re.search(r'[a-z]', password) else 0
    has_digit = 1 if re.search(r'[0-9]', password) else 0
    has_special = 1 if re.search(r'[@$!%*?&]', password) else 0
    return [length, has_upper, has_lower, has_digit, has_special]

# Load dataset
df = pd.read_csv("passwords.csv")

# Extract features
X = df["password"].apply(extract_features).tolist()
y = df["strength"]

# Split
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2)

# Train model
model = LogisticRegression()
model.fit(X_train, y_train)

# Save model
with open("model.pkl", "wb") as f:
    pickle.dump(model, f)

print("Model trained and saved!")