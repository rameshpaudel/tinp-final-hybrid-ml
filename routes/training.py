import ast
import os
from flask import request, jsonify, Blueprint,current_app
import skops.io as sio
from werkzeug.utils import secure_filename 
from models.training import Training
from utils.pe_train_predict import train_model
from utils.url_train_predict import train_url_model
from zipfile import ZIP_DEFLATED
from utils.main import db


training_routes = Blueprint("training", __name__)
   
@training_routes.route('/upload_and_train', methods=['POST'])
def upload_and_train_files():
    if 'file' not in request.files:
        return jsonify({"error": "No file part"}), 400
    file = request.files['file']
    if file.filename == '':
        return jsonify({"error": "No selected file"}), 400
    if file:
        filename = secure_filename(file.filename)
        filepath = os.path.join(current_app.config['UPLOAD_FOLDER'], filename)
        file.save(filepath)
        results, model_file = train_model(filepath)
        
        training = Training(
            results=str(results),
            training_results= ast.literal_eval(results),
            dataset_for='pe_file',
            model_file = model_file
        )
        db.session.add(training)
        db.session.commit()
            
        return jsonify({
            "message": "Models trained and voting classifier saved successfully",
        }), 200

    return jsonify({"error": "Invalid file type"}), 400

@training_routes.route('/upload_and_train_url', methods=['POST'])
def upload_and_train_url():
    if 'file' not in request.files:
        return jsonify({"error": "No file part"}), 400
    file = request.files['file']
    if file.filename == '':
        return jsonify({"error": "No selected file"}), 400
    if file:
        filename = secure_filename(file.filename)
        filepath = os.path.join(current_app.config['UPLOAD_FOLDER'], filename)
        file.save(filepath)
        results, model_file = train_url_model(filepath)
        
        training = Training(
            results=str(results),
            dataset_for='url',
            model_file = model_file
        )
        db.session.add(training)
        db.session.commit()
            
        return jsonify({
            "message": "Url models trained and saved successfully",
        }), 200

    return jsonify({"error": "Invalid file type"}), 400

@training_routes.route('/model_info/pe', methods=['GET'])
def model_info():
    
    BASE_PATH = "uploads/model/"
    latest_model = Training.query.filter_by(dataset_for="pe_file").order_by(Training.created_at.desc()).first()
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
    

    