
import os
import uuid
from utils.main import db,auth
from utils.pe_header_extractor import get_pefile_headers,allowed_file,is_pe_file
from models.user import User
from models.training import Training
from models.scans import ScanHistory
from sqlalchemy.exc import SQLAlchemyError
from flask import jsonify, g, request, current_app, Blueprint
from utils.train_model import predict

webapp = Blueprint("frontend_pages", __name__)
    
'''Scan a file and get malware analysis'''
@webapp.route('/scan/file', methods=['POST'])
def upload_file():
    #Check user is logged in
    token = request.headers.get('Authorization', None)
    if token:
        token = token.split()[1]
        user = User.verify_auth_token(token)
        g.user = user

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
                
        latest_model = Training.query.order_by(Training.created_at.desc()).first()
        prediction = predict(pe_headers, latest_model.model_file)
        
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

@webapp.route('/scan_url', methods=['POST'])
def scan_url():
    return {
        "malware_analysed" : 200,
        "total_scans": 300
    }

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
        "malware_analysed" : 200,
        "total_scans": ScanHistory.get_total_scans(user_id=user_id)
    }
