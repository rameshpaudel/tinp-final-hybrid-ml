import datetime
import numpy as np
import pandas as pd
import skops.io as sio
from flask import jsonify
from sklearn.svm import SVC
from zipfile import ZIP_DEFLATED
from sklearn.preprocessing import LabelEncoder
from sklearn.tree import DecisionTreeClassifier
from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import CountVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.ensemble import RandomForestClassifier,VotingClassifier
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix, recall_score

from utils.api_response import success_message


'''Train all the models and save the final voting classifier and label encode model as persistant model'''
def train_url_model(filepath):
    #Generate unique model name
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

    # Feature Extraction using Count Vectorizer
    vectorizer = CountVectorizer()
    X = vectorizer.fit_transform(data['url'])
    y = data['type']

    # Train-test split
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

    # Define individual models
    lr_model = LogisticRegression(max_iter=500)
    # dt = DecisionTreeClassifier()
    rf_model = RandomForestClassifier()
    svm_model = SVC(probability=True)

    # Create the Voting Classifier
    voting_clf = VotingClassifier(estimators=[
        ('lr', lr_model),
        # ('dt', dt),
        ('rf', rf_model),
        ('svc', svm_model)
    ], voting='soft')

    models = {
        "Logistic Regression": lr_model,
        # "Decision Tree": dt,
        "Random Forest": rf_model,
        "SVM": svm_model,
        "Voting Classifier": voting_clf
    }
    
    sio.dump(le, "uploads/model/url_label_encoder.skops", compression=ZIP_DEFLATED, compresslevel=9)


    #Fit the random forest model
    rf_model.fit(X_train, y_train)
    
    #Fit the SVM model
    svm_model.fit(X_train, y_train)

    #Fit the Decision Tree model
    # dt.fit(X_train, y_train)
    
    # Train the Voting Classifier on the training set
    voting_clf.fit(X_train, y_train)
    
    # Persist the model on disk
    sio.dump(voting_clf, f"uploads/model/voting_{MODEL_FILE}", compression=ZIP_DEFLATED, compresslevel=9)

    results = {}
    # Evaluate the model on the test set
    for name, model in models.items():
        y_train_pred = model.predict(X_train)
        y_test_pred = model.predict(X_test)

        
        train_accuracy = accuracy_score(y_train, y_train_pred)
        test_accuracy = accuracy_score(y_test, y_test_pred)
        class_report = classification_report(y_test, y_test_pred, target_names=le.classes_, output_dict=True, zero_division=1)
        conf_matrix = confusion_matrix(y_test, y_test_pred)

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


''' Predict the probability of the malware'''
def predict_url(url_input, model_file):
    BASE_PATH = "uploads/model/"
    model_path = f"{BASE_PATH}{model_file}"
    unknown_types_model = sio.get_untrusted_types(file=model_path)
    unknown_types_le = sio.get_untrusted_types(file=f"{BASE_PATH}url_label_encoder.skops")

    # Load the saved model and label encoder
    model = sio.load(model_path, trusted=unknown_types_model)
    le = sio.load(f"{BASE_PATH}url_label_encoder.skops", trusted=unknown_types_le)

    # Ensure le is actually a LabelEncoder
    if not isinstance(le, LabelEncoder):
        raise TypeError("The loaded 'le' object is not a LabelEncoder")
    
    # Url to test
    X = url_input

    # Make predictions
    y_pred = model.predict(X)
    y_pred_proba = model.predict_proba(X)

    # Convert numeric predictions back to labels
    predictions = le.inverse_transform(y_pred)

    # Prepare results
    results = []
    for i, pred in enumerate(predictions):
        result = {
            "prediction": pred,
            "probability": {
                le.inverse_transform([j])[0]: prob for j, prob in enumerate(y_pred_proba[i])
            }
        }
        results.append(result)

    return results
