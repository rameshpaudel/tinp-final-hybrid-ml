import datetime
import numpy as np
import pandas as pd
import skops.io as sio
import json
from flask import jsonify
from sklearn.svm import SVC
from zipfile import ZIP_DEFLATED
from sklearn.preprocessing import LabelEncoder
from sklearn.tree import DecisionTreeClassifier
from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.ensemble import RandomForestClassifier, VotingClassifier
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix, recall_score
from utils.pe_train_predict import serialize_numpy
from utils.api_response import success_message
from urllib.parse import urlparse
import re
from tld import get_tld
from scipy.sparse import hstack, csr_matrix


def extract_url_features(url):
    features = {}
    
    # Length of the URL
    features['url_length'] = len(url)
    
    # Number of dots, hyphens, underscores, slashes, question marks, and equal signs in the URL
    features['dot_count'] = url.count('.')
    features['hyphen_count'] = url.count('-')
    features['underscore_count'] = url.count('_')
    features['slash_count'] = url.count('/')
    features['question_mark_count'] = url.count('?')
    features['equal_sign_count'] = url.count('=')
    
    # Number of digits in the URL
    features['digit_count'] = sum(c.isdigit() for c in url)
    
    # Presence of 'https'
    features['https_present'] = int('https' in url.lower())
    
    # Get the TLD
    try:
        tld = get_tld(url, fail_silently=True)
        features['tld'] = tld if tld else ''
    except:
        features['tld'] = ''
    
    # Extracted domain
    parsed_url = urlparse(url)
    features['domain'] = parsed_url.netloc
    
    # Length of the domain
    features['domain_length'] = len(features['domain'])
    
    # Presence of IP address in the URL
    features['has_ip'] = int(bool(re.match(r'\d+\.\d+\.\d+\.\d+', parsed_url.netloc)))
    
    return features

def train_url_model(filepath):
    # Generate unique model name
    MODEL_FILE = datetime.datetime.now().strftime("%Y-%m-%d_%I-%M-%S_%p")+'url_model.skops'
    
    # Load the CSV file
    data = pd.read_csv(filepath)

    # Check if 'Type' column is present
    if 'type' not in data.columns:
        return jsonify({"error": "CSV file is missing the required 'Type' column"}), 400

    # Initialize the Label Encoder
    le = LabelEncoder()

    # Encode the 'type' column (phishing, benign, defacement, malware)
    data['type'] = le.fit_transform(data['type'])

    # Extract features
    features_df = data['url'].apply(extract_url_features).apply(pd.Series)
    
    # Feature Extraction using TfidfVectorizer
    vectorizer = TfidfVectorizer(max_features=10000)
    X_tfidf = vectorizer.fit_transform(data['url'])
    
    # Combine TfidfVectorizer features with extracted features
    X = np.hstack((X_tfidf.toarray(), features_df.values))
    y = data['type']
    
    # Save the fitted vectorizer
    sio.dump(vectorizer, "uploads/model/url_vectorizer.skops", compression=ZIP_DEFLATED, compresslevel=9)
    
    print("Vectorized the data")
    print(X.shape)

    # Train-test split
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.7, random_state=42)

    # Define individual models
    dt = DecisionTreeClassifier()
    rf_model = RandomForestClassifier(n_jobs=-1)

    # Create the Voting Classifier
    voting_clf = VotingClassifier(estimators=[
        ('dt', dt),
        ('rf', rf_model),
    ], voting='soft')

    models = {
        "Decision Tree": dt,
        "Random Forest": rf_model,
        "Voting Classifier": voting_clf
    }
    
    sio.dump(le, "uploads/model/url_label_encoder.skops", compression=ZIP_DEFLATED, compresslevel=9)

    # Fit the models
    for name, model in models.items():
        model.fit(X_train, y_train)
    
    # Persist the voting classifier on disk
    sio.dump(voting_clf, f"uploads/model/voting_{MODEL_FILE}", compression=ZIP_DEFLATED, compresslevel=9)

    results = {}
    # Evaluate the models on the test set
    for name, model in models.items():
        y_train_pred = model.predict(X_train)
        y_test_pred = model.predict(X_test)

        train_accuracy = accuracy_score(y_train, y_train_pred)
        test_accuracy = accuracy_score(y_test, y_test_pred)
        class_report = serialize_numpy(classification_report(y_test, y_test_pred, target_names=le.classes_, output_dict=True, zero_division=1))
        conf_matrix = confusion_matrix(y_test, y_test_pred).tolist()

        # Fix serialization issue while sending API response
        serialized_report = {}
        for k, v in class_report.items():
            if isinstance(v, dict):
                serialized_report[k] = {kk: vv for kk, vv in v.items()}
            else:
                serialized_report[k] = v
                
        results[name] = {
            "train_accuracy": train_accuracy,
            "test_accuracy": test_accuracy,
            "classification_report": serialized_report,
            "confusion_matrix": conf_matrix
        }
    
    return results, f'voting_{MODEL_FILE}'

def predict_url(url_input, model_file):
    BASE_PATH = "uploads/model/"
    model_path = f"{BASE_PATH}{model_file}"
    unknown_types_model = sio.get_untrusted_types(file=model_path)
    unknown_types_le = sio.get_untrusted_types(file=f"{BASE_PATH}url_label_encoder.skops")

    # Load the saved model and label encoder
    model = sio.load(model_path, trusted=unknown_types_model)
    le = sio.load(f"{BASE_PATH}url_label_encoder.skops", trusted=unknown_types_le)
    vectorizer = sio.load(f"{BASE_PATH}_url_vectorizer.skops", trusted=sio.get_untrusted_types(file=f"{BASE_PATH}url_vectorizer.skops"))

    # Ensure le is actually a LabelEncoder
    if not isinstance(le, LabelEncoder):
        raise TypeError("The loaded 'le' object is not a LabelEncoder")
    
    # Extract features from the URL
    url_features = extract_url_features(url_input)
    
    # Transform the URL using TfidfVectorizer
    X_tfidf = vectorizer.transform([url_input])

    
    
    # Convert url_features dictionary to a list of numeric values
    feature_values = []
    for key, value in url_features.items():
        if key not in ['tld', 'domain']:  # Exclude 'tld' and 'domain' from numeric features
            if isinstance(value, str):
                if value == '':
                    feature_values.append(0.0)
                else:
                    try:
                        feature_values.append(float(value))
                    except ValueError:
                        feature_values.append(0.0)
            else:
                feature_values.append(float(value))

    # Convert feature_values to a numpy array and reshape to 2D
    feature_array = np.array(feature_values).reshape(1, -1)

    # Ensure X_tfidf is 2D
    X_tfidf_array = X_tfidf.toarray()

    print(f"Shape of X_tfidf_array: {X_tfidf_array.shape}")  # Debugging line
    print(f"Shape of feature_array: {feature_array.shape}")  # Debugging line

    # Combine TfidfVectorizer features with extracted features
    X = np.hstack((X_tfidf_array, feature_array))

    # Handle any remaining NaN or inf values
    X = np.nan_to_num(X, nan=0.0, posinf=0.0, neginf=0.0)

    print(f"Shape of X: {X.shape}")  # Debugging line

    # Make predictions
    y_pred = model.predict(X)
    y_pred_proba = model.predict_proba(X)

    confidence_scores = np.max(y_pred_proba, axis=1)

    # Convert numeric predictions back to labels
    predictions = le.inverse_transform(y_pred)

    # Prepare results
    results = []
    for i, pred in enumerate(predictions):
        result = {
            "confidence_score": confidence_scores[0],
            "prediction": pred,
            "probability": {
                le.inverse_transform([j])[0]: prob for j, prob in enumerate(y_pred_proba[i])
            }
        }
        results.append(result)

    return results[0]