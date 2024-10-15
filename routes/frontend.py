
import os
import uuid
import ast
from utils.main import db,auth
from user_agents import parse
from utils.pe_header_extractor import get_pefile_headers,allowed_file,is_pe_file
from models.user import User
from models.training import Training
from models.scans import ScanHistory, URLScanHistory
from sqlalchemy.exc import SQLAlchemyError
from flask import jsonify, g, request, current_app, Blueprint
from utils.pe_train_predict import predict_file
from utils.url_train_predict import predict_url

webapp = Blueprint("frontend_pages", __name__)

def get_user_agent_info(user_agent):
    user_agent = parse(user_agent.string)
    return {
        'ip_address': request.remote_addr,
        'user_agent': str(user_agent),
        'browser': user_agent.browser.family,
        'os': user_agent.os.family,
        'device': user_agent.device.family
    }
def get_logged_in_user():
    #Check user is logged in
    token = request.headers.get('Authorization', None)
    if token:
        token = token.split()[1]
        user = User.verify_auth_token(token)
        g.user = user
        
'''Scan and predict the results from pe_header input directly'''
@webapp.route('/scan/pe_header', methods=["POST"])
def predict_from_pe():
    pe_headers = request.get_json()

    latest_model = Training.query.filter_by(dataset_for="pe_file").order_by(Training.created_at.desc()).first()
    prediction = predict_file(pe_headers, latest_model.model_file)
    scan_data = {
        "file_name": "PE_HEADERS_ONLY",
        "hashed_name": "PE_HEADERS_ONLY",
        "details": pe_headers
    }
    # Collect and track user data about browser
    scan_data['request_info'] = get_user_agent_info(request.user_agent)
    try:
        scan = ScanHistory(**scan_data)
        scan.results = prediction
        db.session.add(scan)
        db.session.commit()
    except SQLAlchemyError as db_error:
        db.session.rollback()
        print(f"Database error: {str(db_error)}")
        # Log this error for admin review
    return jsonify(prediction),200
    
    
'''Scan a file and get malware analysis'''
@webapp.route('/scan/file', methods=['POST'])
def scan_and_predict():
    get_logged_in_user()

    # Check if the post request has the file part
    if 'file' not in request.files:
        return jsonify({'error': 'No file part found in the request'}), 400

    file = request.files['file']
    
    # If user does not select file, browser also
    # submit an empty part without filename
    if file.filename == '':
        return jsonify({'error': 'No file selected'}), 400
    
    if file and allowed_file(file.filename):
        # Generate a secure random filename
        filename = str(uuid.uuid4())
        file_path = os.path.join(current_app.config['UPLOAD_FOLDER'], filename)
        
        try:
            ## Try saving the file to the filepath 
            file.save(file_path)
            
            # Check if it's actually a PE file
            if not is_pe_file(file_path):
                os.remove(file_path)
                return jsonify({'error': 'Not a valid PE file'}), 400
            
            # Extract PE file headers
            pe_headers, scan_data = get_pefile_headers(original_filename=file.filename,hashed_filename=filename,file_path=file_path)
        except Exception as e:
            return jsonify({'error': str(e)}), 500
        finally:
            # Clean up: remove the uploaded file
            if os.path.exists(file_path):
                os.remove(file_path)
                
        latest_model = Training.query.filter_by(dataset_for="pe_file").order_by(Training.created_at.desc()).first()
        prediction = predict_file(pe_headers, latest_model.model_file)
        
        try:
            scan = ScanHistory(**scan_data)
            scan.results = prediction
            db.session.add(scan)
            db.session.commit()
        except SQLAlchemyError as db_error:
            db.session.rollback()
            print(f"Database error: {str(db_error)}")
            # Log this error for admin review
        return jsonify(prediction),200
    else:
        return jsonify({'error': 'File type not allowed'}), 400


'''Scan the url and return the classification of url'''
@webapp.route('/scan/url', methods=['POST'])
def scan_url():
    # Check if the user is logged in
    get_logged_in_user()
    latest_model = Training.query.filter_by(dataset_for="url").order_by(Training.created_at.desc()).first()
    user_id = None
    if g.user is not None:
        user_id = g.user.id
    # Extract the URL from the request
    data = request.json  # or request.form if it's a form submission
    url = data.get('url')
    
    if not url:
        return jsonify({"error": "URL is required"}), 400
    
    # Call the prediction function
    result = predict_url(url, latest_model.model_file)
    

    # Save the scan to the database
    url_scan = URLScanHistory(
        url = url,
        results = str(result),
        details = ast.literal_eval(result),
        request_info = get_user_agent_info(request.user_agent),
        user_id = user_id,
        status = result['prediction']
    )
    db.session.add(url_scan)
    db.session.commit()
    
    return jsonify(result)


#Get user stats about the scan
@auth.login_required()
@webapp.route('/user_stats', methods=['GET'])
def current_user_stats():
    token = request.headers.get('Authorization', None)
    user_id = None
    if token:
        token = token.split()[1]
        user = User.verify_auth_token(token)
        user_id = user.id
    return {
        "malware_found" : 200,
        "total_scans": ScanHistory.get_total_scans(user_id=user_id)
    }
