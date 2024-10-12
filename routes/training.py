from operator import index
import os
import time
import numpy as np
import pandas as pd
import json
from flask import Flask, request, jsonify, Blueprint,current_app
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier, BaggingClassifier,VotingClassifier
from sklearn.svm import SVC
from sklearn.preprocessing import LabelEncoder
from sklearn.tree import DecisionTreeClassifier
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix, recall_score
import skops.io as sio
from werkzeug.utils import secure_filename 
from models.training import Training
import datetime
from zipfile import ZIP_DEFLATED
from utils.api_response import response_with_message
from utils.main import db


training_routes = Blueprint("training", __name__)

'''Serialize the numpy datasets to store in the databser'''
def serialize_numpy(obj):
        if isinstance(obj, np.integer):
            return int(obj)
        elif isinstance(obj, np.floating):
            return float(obj)
        elif isinstance(obj, np.ndarray):
            return obj.tolist()
        elif isinstance(obj, dict):
            return {k: serialize_numpy(v) for k, v in obj.items()}
        elif isinstance(obj, list):
            return [serialize_numpy(item) for item in obj]
        return obj  # Default case
    
@training_routes.route('/upload_and_train', methods=['POST'])
def upload_and_train():
    if 'file' not in request.files:
        return jsonify({"error": "No file part"}), 400
    file = request.files['file']
    if file.filename == '':
        return jsonify({"error": "No selected file"}), 400
    if file:
        filename = secure_filename(file.filename)
        filepath = os.path.join(current_app.config['UPLOAD_FOLDER'], filename)
        file.save(filepath)
        return train_model(filepath)
    return jsonify({"error": "Invalid file type"}), 400

def train_model(filepath):
    #Generate unique model name
    MODEL_FILE = datetime.datetime.now().strftime("%Y-%m-%d_%I-%M-%S_%p")+'pe_model.skops'
    # Load the CSV file
    df = pd.read_csv(filepath)

    # Check if 'Type' column is present
    if 'Type' not in df.columns:
        return jsonify({"error": "CSV file is missing the required 'Type' column"}), 400

    # Identify and extract feature columns (all columns except 'Type', 'SHA256')
    feature_columns = [col for col in df.columns if col not in ['SHA256', 'Type']]
 
    # Ensure there are feature columns
    if not feature_columns:
        return jsonify({"error": "CSV file does not contain any feature columns"}), 400

    # Separate features and labels
    X = df[feature_columns].values
    y = df['Type'].values

    labels = ['Benign', 'RedLineStealer', 'Downloader', 'RAT', 'BankingTrojan', 'SnakeKeyLogger', 'Spyware']

    # Encode labels if they're not already numeric
    le = LabelEncoder()  
    y = le.fit_transform(y)
    
    # Fit the LabelEncoder to the labels
    le.fit(labels)
    
    # Split the data
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.8, random_state=42)


    # Initialize individual models
    rf_model = RandomForestClassifier(n_estimators=100, random_state=42)
    svm_model = SVC(probability=True, random_state=42)
    dt_model = DecisionTreeClassifier(random_state=42)

    # Create voting classifier
    voting_model = VotingClassifier(
        estimators=[('rf', rf_model), ('svm', svm_model), ('dt', dt_model)],
        voting='soft'
    )


    #Fit the random forest model
    rf_model.fit(X_train, y_train)
    
    #Fit the SVM model
    svm_model.fit(X_train, y_train)

    #Fit the Decision Tree model
    dt_model.fit(X_train, y_train)
    
    
    # Train the voting classifier
    voting_model.fit(X_train, y_train)
    sio.dump(le, "uploads/model/label_encoder.skops", compression=ZIP_DEFLATED, compresslevel=9)

    # Save the model using skops
    sio.dump(voting_model, f"uploads/model/voting_{MODEL_FILE}", compression=ZIP_DEFLATED, compresslevel=9)

    # Calculate accuracies and metrics for individual models and voting classifier
    models = {
        "Random Forest": rf_model,
        "SVM": svm_model,
        "Decision Tree": dt_model,
        "Voting Classifier": voting_model
    }

    results = {}
    '''Generate the reports and stats for each of the ml algorithm'''
    for name, model in models.items():
        y_train_pred = model.predict(X_train)
        y_test_pred = model.predict(X_test)

        train_accuracy = serialize_numpy(accuracy_score(y_train, y_train_pred))
        test_accuracy = serialize_numpy(accuracy_score(y_test, y_test_pred))
        class_report = classification_report(y_test, y_test_pred, target_names=le.classes_, output_dict=True)
        conf_matrix = serialize_numpy(confusion_matrix(y_test, y_test_pred))

        # Fix serialization issue while sending API response
        serialized_report = {}
        for k, v in class_report.items():
            if isinstance(v, dict):
                serialized_report[k] = {serialize_numpy(kk): serialize_numpy(vv) for kk, vv in v.items()}
            else:
                serialized_report[k] = serialize_numpy(v)
                
        results[name] = {
            "train_accuracy": train_accuracy,
            "test_accuracy": test_accuracy,
            "classification_report": serialized_report,
            "confusion_matrix": conf_matrix
        }
    
    
    training = Training(
        results=str(results),
        dataset_for='pe_file',
        model_file = f"voting_{MODEL_FILE}"
        )
    db.session.add(training)
    db.session.commit()
         
    return jsonify({
        "message": "Models trained and voting classifier saved successfully",
    }), 200


def predict(json_input):
    BASE_PATH = "uploads/model/"
    latest_model = Training.query.order_by(Training.created_at.desc()).first()
    model_path = f"{BASE_PATH}{latest_model.model_file}"

    unknown_types_model = sio.get_untrusted_types(file=model_path)
    unknown_types_le = sio.get_untrusted_types(file=f"{BASE_PATH}label_encoder.skops")

    # Load the saved model and label encoder
    model = sio.load(model_path, trusted=unknown_types_model)
    le = sio.load(f"{BASE_PATH}label_encoder.skops", trusted=unknown_types_le)

    # Ensure le is actually a LabelEncoder
    if not isinstance(le, LabelEncoder):
        raise TypeError("The loaded 'le' object is not a LabelEncoder")
    
    # Load the CSV file for prediction
    df = pd.json_normalize(json_input)
    
    # Identify feature columns (all columns except 'SHA256' if present)
    feature_columns = [col for col in df.columns if col != 'SHA256']
    
    # Ensure there are feature columns
    if not feature_columns:
        return jsonify({"error": "CSV file does not contain any feature columns"}), 400

    # Extract features
    X = df[feature_columns].values

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

@training_routes.route('/model_info', methods=['GET'])
def model_info():
    
    BASE_PATH = "uploads/model/"
    latest_model = Training.query.order_by(Training.created_at.desc()).first()
    model_path = f"{BASE_PATH}{latest_model.model_file}"
    
    
    #Check if the model exists 
    if not os.path.exists(model_path):
        return jsonify({"error": "Model not found. Please train the model first."}), 404

    # Load the model using skops
    model = sio.load(model_path, trusted=sio.get_untrusted_types(file=model_path))
    # List all the parameters
    params = {key: str(value) for key, value in model.get_params().items()}

    return jsonify({
        "model_type": str(type(model)),
        "parameters": params
    }), 200
    

    