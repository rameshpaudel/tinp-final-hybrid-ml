import ast
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
from sklearn.ensemble import RandomForestClassifier,VotingClassifier,GradientBoostingClassifier
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix, recall_score,roc_auc_score

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

'''Train all the models and save the final voting classifier and label encode model as persistant model'''
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

    # Define the mapping from numeric values to labels
    label_mapping = {
        0: 'Benign',
        1: 'RedLineStealer',
        2: 'Downloader',
        3: 'RAT',
        4: 'BankingTrojan',
        5: 'SnakeKeyLogger',
        6: 'Spyware'
    }
    df['Type'] = df['Type'].map(label_mapping)
    # Separate features and labels
    X = df[feature_columns].values
    y = df['Type'].values

    # Encode labels if they're not already numeric
    le = LabelEncoder()  
    # Fit the LabelEncoder to the labels
    y_encoded = le.fit_transform(y)
    
    # Split the data
    X_train, X_test, y_train, y_test = train_test_split(X, y_encoded, test_size=0.3, random_state=42)


    # Initialize individual models
    rf_model = RandomForestClassifier(n_estimators=80, random_state=42)
    # svm_model = SVC(probability=True, random_state=42)
    gbm_model = GradientBoostingClassifier(random_state=42)


    # Create voting classifier
    voting_model = VotingClassifier(
        estimators=[
            ('rf', rf_model), 
            # ('svm', svm_model), 
            ('gbm', gbm_model)
            ],
        voting='soft'
    )


    #Fit the random forest model
    rf_model.fit(X_train, y_train)
    
    #Fit the SVM model
    # svm_model.fit(X_train, y_train)

    #Fit the Decision Tree model
    gbm_model.fit(X_train, y_train)
    
    
    # Train the voting classifier
    voting_model.fit(X_train, y_train)
    #Save the model to the filesystem
    sio.dump(le, "uploads/model/label_encoder.skops", compression=ZIP_DEFLATED, compresslevel=9)

    # Save the model using skops
    sio.dump(voting_model, f"uploads/model/voting_{MODEL_FILE}", compression=ZIP_DEFLATED, compresslevel=9)

    # Calculate accuracies and metrics for individual models and voting classifier
    models = {
        "Random Forest": rf_model,
        # "SVM": svm_model,
        "Gradient Boosting": gbm_model,
        "Voting Classifier": voting_model
    }

    results = {}
    '''Generate the reports and stats for each of the ml algorithm'''
    for name, model in models.items():
        y_train_pred = model.predict(X_train)
        y_test_pred = model.predict(X_test)

        train_accuracy = serialize_numpy(accuracy_score(y_train, y_train_pred))
        test_accuracy = serialize_numpy(accuracy_score(y_test, y_test_pred))
        class_report = classification_report(y_test, y_test_pred, target_names=le.classes_, output_dict=True, zero_division=1)
        conf_matrix = confusion_matrix(y_test, y_test_pred).tolist()
         # Recall = True Positives / (True Positives + False Negatives)

        recall = recall_score(y_test, y_test_pred, average='weighted')
        
        # Receiver Operating Characteristic Area Under the Curve is a metric that measures the model's ability to distinguish between positive and negative classes.
        roc_auc = roc_auc_score(y_test, model.predict_proba(X_test), multi_class='ovr', average='weighted')


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
            "confusion_matrix": conf_matrix,
            "recall": recall,
            "roc_auc": roc_auc
        }
    
    
    return results, f"voting_{MODEL_FILE}"


## Predict the probability of the malware
def predict_file(json_input, model_file):
    BASE_PATH = "uploads/model/"
    model_path = f"{BASE_PATH}{model_file}"
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
    
    confidence_scores = np.max(y_pred_proba, axis=1)
    
    
    # Convert numeric predictions back to labels
    predictions = le.inverse_transform(y_pred)

    # Prepare results
    results = []
    for i, pred in enumerate(predictions):
        result = {
            "confidence_scores": confidence_scores[0],
            "prediction": pred,
            "probability": {
                le.inverse_transform([j])[0]: prob for j, prob in enumerate(y_pred_proba[i])
            }
        }
        results.append(result)

    return results
