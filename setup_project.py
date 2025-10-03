
# setup_project.py - Run this to create all project files
import os
import joblib
import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import StandardScaler

print("🚀 Setting up AI Phishing Detection Project...")

# Create directories
os.makedirs('templates', exist_ok=True)
os.makedirs('static', exist_ok=True)

print("✅ Created directories")

# Create sample dataset and train model
print("🤖 Training AI models...")

# Generate sample data
np.random.seed(42)
n_samples = 1000

# Features for legitimate URLs
legit_data = []
for i in range(500):
    legit_data.append([
        np.random.randint(15, 30),  # url_length (shorter for legit)
        2,  # dot_count
        0,  # hyphen_count (fewer hyphens)
        0,  # underscore_count
        2,  # slash_count
        0,  # digit_count
        1,  # has_https (usually https)
        0,  # has_ip
        0,  # has_at_symbol
        0,  # double_slash_redirecting
        1,  # subdomain_count
        0,  # suspicious_keywords (none for legit)
        0,  # has_port
        0   # query_params_count
    ])

# Features for phishing URLs
phishing_data = []
for i in range(500):
    phishing_data.append([
        np.random.randint(40, 80),  # url_length (longer for phishing)
        np.random.randint(2, 4),    # dot_count
        np.random.randint(2, 6),    # hyphen_count (more hyphens)
        0,  # underscore_count
        2,  # slash_count
        np.random.randint(0, 5),    # digit_count
        np.random.randint(0, 2),    # has_https (mixed)
        0,  # has_ip
        0,  # has_at_symbol
        0,  # double_slash_redirecting
        np.random.randint(1, 4),    # subdomain_count
        np.random.randint(1, 4),    # suspicious_keywords (more for phishing)
        0,  # has_port
        np.random.randint(0, 3)     # query_params_count
    ])

# Combine data
X = np.array(legit_data + phishing_data)
y = np.array([0]*500 + [1]*500)  # 0=legitimate, 1=phishing

# Train Random Forest model
model = RandomForestClassifier(n_estimators=100, random_state=42)
model.fit(X, y)

# Train scaler
scaler = StandardScaler()
scaler.fit(X)

# Save models
joblib.dump(model, 'best_phishing_model.pkl')
joblib.dump(scaler, 'feature_scaler.pkl')

# Save dataset
feature_names = [
    'url_length', 'dot_count', 'hyphen_count', 'underscore_count',
    'slash_count', 'digit_count', 'has_https', 'has_ip',
    'has_at_symbol', 'double_slash_redirecting', 'subdomain_count',
    'suspicious_keywords', 'has_port', 'query_params_count'
]

df = pd.DataFrame(X, columns=feature_names)
df['label'] = y
df.to_csv('phishing_dataset.csv', index=False)

print("✅ AI models trained and saved")
print("✅ Dataset created")
print("🎉 Setup completed! You can now run the Flask app.")
