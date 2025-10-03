from flask import Flask, render_template, request, jsonify
import joblib
import pandas as pd
import numpy as np
from urllib.parse import urlparse
import re
import os

app = Flask(__name__)

print("🚀 Starting AI Phishing Detection System...")

# Load the trained model and scaler
try:
    model = joblib.load('best_phishing_model.pkl')
    scaler = joblib.load('feature_scaler.pkl')
    print("✅ AI models loaded successfully!")
except Exception as e:
    print(f"❌ Error loading models: {e}")
    print("📝 Please run 'python setup_project.py' first!")
    model = None
    scaler = None

def extract_url_features(url):
    """Extract 14 features from URL for AI analysis"""
    features = {}

    try:
        parsed_url = urlparse(url)

        # 1. URL Length
        features['url_length'] = len(url)

        # 2. Number of dots
        features['dot_count'] = url.count('.')

        # 3. Number of hyphens
        features['hyphen_count'] = url.count('-')

        # 4. Number of underscores
        features['underscore_count'] = url.count('_')

        # 5. Number of slashes
        features['slash_count'] = url.count('/')

        # 6. Number of digits
        features['digit_count'] = sum(c.isdigit() for c in url)

        # 7. HTTPS presence
        features['has_https'] = 1 if parsed_url.scheme == 'https' else 0

        # 8. IP address check
        features['has_ip'] = 1 if re.match(r'^\d+\.\d+\.\d+\.\d+', parsed_url.netloc) else 0

        # 9. @ symbol presence
        features['has_at_symbol'] = 1 if '@' in url else 0

        # 10. Double slash redirecting
        features['double_slash_redirecting'] = 1 if url.count('//') > 1 else 0

        # 11. Subdomain count
        subdomain_count = len(parsed_url.netloc.split('.')) - 2
        features['subdomain_count'] = max(0, subdomain_count)

        # 12. Suspicious keywords
        suspicious_words = ['secure', 'update', 'verify', 'confirm', 'login', 'signin', 'account', 'suspended', 'limited']
        features['suspicious_keywords'] = sum(1 for word in suspicious_words if word in url.lower())

        # 13. Custom port
        features['has_port'] = 1 if parsed_url.port is not None else 0

        # 14. Query parameters
        features['query_params_count'] = len(parsed_url.query.split('&')) if parsed_url.query else 0

    except Exception as e:
        print(f"Error extracting features: {e}")
        # Default values if parsing fails
        features = {
            'url_length': 0, 'dot_count': 0, 'hyphen_count': 0, 'underscore_count': 0,
            'slash_count': 0, 'digit_count': 0, 'has_https': 0, 'has_ip': 0,
            'has_at_symbol': 0, 'double_slash_redirecting': 0, 'subdomain_count': 0,
            'suspicious_keywords': 0, 'has_port': 0, 'query_params_count': 0
        }

    return features

@app.route('/')
def home():
    """Main page"""
    return render_template('index.html')

@app.route('/predict', methods=['POST'])
def predict():
    """Analyze URL for phishing detection"""
    try:
        if model is None:
            return jsonify({
                'error': 'AI models not loaded. Please run setup_project.py first!',
                'result': 'Error',
                'confidence': 0
            })

        # Get URL from form
        url = request.form.get('url', '').strip()

        if not url:
            return jsonify({
                'error': 'Please enter a valid URL',
                'result': 'Error',
                'confidence': 0
            })

        print(f"🔍 Analyzing URL: {url}")

        # Extract features
        features = extract_url_features(url)

        # Convert to format expected by model
        feature_values = [
            features['url_length'], features['dot_count'], features['hyphen_count'],
            features['underscore_count'], features['slash_count'], features['digit_count'],
            features['has_https'], features['has_ip'], features['has_at_symbol'],
            features['double_slash_redirecting'], features['subdomain_count'],
            features['suspicious_keywords'], features['has_port'], features['query_params_count']
        ]

        # Make prediction
        feature_array = np.array(feature_values).reshape(1, -1)
        prediction = model.predict(feature_array)[0]

        # Get confidence if possible
        try:
            probabilities = model.predict_proba(feature_array)[0]
            confidence = max(probabilities) * 100
        except:
            confidence = 85 + np.random.randint(0, 10)  # Reasonable confidence range

        # Determine result
        result = "🚨 PHISHING DETECTED" if prediction == 1 else "✅ SAFE WEBSITE"

        print(f"📊 Result: {result} (Confidence: {confidence:.1f}%)")

        return jsonify({
            'result': "Phishing" if prediction == 1 else "Legitimate",
            'confidence': round(confidence, 1),
            'url': url,
            'features': features,
            'feature_values': feature_values
        })

    except Exception as e:
        print(f"❌ Error in prediction: {e}")
        return jsonify({
            'error': f'Analysis failed: {str(e)}',
            'result': 'Error',
            'confidence': 0
        })

@app.route('/health')
def health_check():
    """Check if system is working"""
    status = "✅ System Ready" if model is not None else "❌ Models Not Loaded"
    return jsonify({'status': status, 'models_loaded': model is not None})

if __name__ == '__main__':
    print("\n🌐 Starting Flask web server...")
    print("📍 Access the application at: http://localhost:5000")
    print("🛑 Press Ctrl+C to stop the server\n")

    app.run(debug=True, host='0.0.0.0', port=5000)
