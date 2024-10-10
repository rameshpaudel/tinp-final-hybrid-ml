import os
import time
import numpy as np
import pandas as pd
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
from utils.main import db

training_routes = Blueprint("training", __name__)

MODEL_FILE = datetime.datetime.now().strftime("%Y-%m-%d_%I-%M-%S_%p")+'pe_model.skops'

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
        print("END filepath")
        print(filepath)
        file.save(filepath)
        return train_model(filepath)
    return jsonify({"error": "Invalid file type"}), 400


def train_model(filepath):
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
    
    # Start timing for data loading and preprocessing
    start_time = time.time()
    
    # Load the CSV file
    df = pd.read_csv(filepath)

    
    # Check if 'legitimate' column is present
    if 'Type' not in df.columns:
        return jsonify({"error": "CSV file is missing the required 'legitimate' column"}), 400

    # Identify feature columns (all columns except 'legitimate', 'Name', 'md5')
    feature_columns = [col for col in df.columns if col not in ['SHA256', 'Type']]
    print("FEATURED COLUMNS")
    print(feature_columns)

    # Ensure there are feature columns
    if not feature_columns:
        return jsonify({"error": "CSV file does not contain any feature columns"}), 400

    # Separate features and labels
    X = df[feature_columns].values
    y = df['Type'].values


    # Encode labels if they're not already numeric
    le = LabelEncoder()  
    y = le.fit_transform(y)

    # Split the data
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

    preprocessing_time = time.time() - start_time

    # Start timing for model training
    training_start = time.time()

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

    training_time = time.time() - training_start
    # Save the model using skops
    sio.dump(voting_model, "uploads/model/voting_"+MODEL_FILE, compression=ZIP_DEFLATED, compresslevel=9)

    # Calculate accuracies and metrics for individual models and voting classifier
    models = {
        "Random Forest": rf_model,
        "SVM": svm_model,
        "Decision Tree": dt_model,
        "Voting Classifier": voting_model
    }

    results = {}

    for name, model in models.items():
        y_train_pred = model.predict(X_train)
        y_test_pred = model.predict(X_test)

        train_accuracy = accuracy_score(y_train, y_train_pred)
        test_accuracy = accuracy_score(y_test, y_test_pred)
        class_report = classification_report(y_test, y_test_pred, target_names=le.classes_, output_dict=True)
        conf_matrix = confusion_matrix(y_test, y_test_pred)

        # Fix serialization issue while sending API response
        serialized_report = {}
        for k, v in class_report.items():
            if isinstance(v, dict):
                serialized_report[k] = {kk: serialize_numpy(vv) for kk, vv in v.items()}
            else:
                serialized_report[k] = serialize_numpy(v)
                
        results[name] = {
            "train_accuracy": serialize_numpy(train_accuracy),
            "test_accuracy": serialize_numpy(test_accuracy),
            "classification_report": serialized_report,
            "confusion_matrix": serialize_numpy(conf_matrix)
        }
        print("HERE "+ name)
        print(results[name])
        # Save the data to the training set    
        Training(
            training_results=jsonify(results[name]),
            dataset_for=name,
            model_file = MODEL_FILE,
            )
        db.session.commit()
         

    return jsonify({
        "message": "Models trained and voting classifier saved successfully",
        "results": results,
        "preprocessing_time": preprocessing_time,
        "training_time": training_time,
        "total_samples": len(y),
        "legitimate_samples": sum(y == 0),
        "malware_samples": sum(y == 1)
    }), 200


# @training_routes.route('/predict', methods=['POST'])
# def predict():
#     if not os.path.exists(MODEL_FILE):
#         return jsonify({"error": "Model not found. Please train the model first."}), 404

#     if 'file_path' not in request.json:
#         return jsonify({"error": "Please provide a file path for prediction"}), 400

#     file_path = request.json['file_path']

#     # Start timing for feature extraction
#     feature_extraction_start = time.time()
#     features = extract_pe_features(file_path)
#     feature_extraction_time = time.time() - feature_extraction_start

#     if not features:
#         return jsonify({"error": "Unable to extract features from the provided file"}), 400

#     # Load the model using skops
#     model = sio.load(MODEL_FILE, trusted=True)

#     # Start timing for prediction
#     prediction_start = time.time()
#     prediction = model.predict([features])[0]
#     probabilities = model.predict_proba([features])[0]
#     prediction_time = time.time() - prediction_start

#     return jsonify({
#         "prediction": int(prediction),
#         "class": "malware" if prediction == 1 else "benign",
#         "probabilities": probabilities.tolist(),
#         "feature_extraction_time": feature_extraction_time,
#         "prediction_time": prediction_time
#     }), 200

@training_routes.route('/model_info', methods=['GET'])
def model_info():
    if not os.path.exists(MODEL_FILE):
        return jsonify({"error": "Model not found. Please train the model first."}), 404

    # Load the model using skops
    model = sio.load(MODEL_FILE, trusted=True)

    # Get model metadata
    metadata = sio.get_metadata(MODEL_FILE)

    return jsonify({
        "model_type": str(type(model)),
        "sklearn_version": metadata.get("sklearn_version", "Unknown"),
        "python_version": metadata.get("python_version", "Unknown"),
        "created_on": metadata.get("created_on", "Unknown"),
        "feature_importance": model.feature_importances_.tolist(),
        "n_estimators": model.n_estimators,
        "max_depth": model.max_depth
    }), 200

