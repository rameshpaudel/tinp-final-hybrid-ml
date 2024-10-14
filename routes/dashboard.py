
import jwt
import ast
import datetime
from flask import jsonify, g, request, current_app, Blueprint
from utils.api_response import respond_success_data
from models.training import Training
from models.user import User
from models.scans import ScanHistory
from utils.main import db, auth

'''All the routes for the dashboard only accessible by the administrator will be placed here'''

dashboard_routes = Blueprint("dashboard_routes", __name__, url_prefix="/dashboard")

'''Get the stats about the application'''
@auth.login_required(role='admin')
@dashboard_routes.route('/stats', methods=['GET'])
def dash_stats():
    
    return {
        "malware_analysed" : 200,
        "total_scans": ScanHistory.get_total_scans()
    }

'''Get the users list'''
@auth.login_required(role='admin') 
@dashboard_routes.route('/users', methods=['GET'])   
def get_users():
    users_list = []
    for user in User.query.all():
            users_list.append(user.to_dict())
    return respond_success_data(data=users_list),200

'''Get individual user's information when id is provided '''
@auth.login_required(role='admin')
@dashboard_routes.route('/user/<int:user_id>', methods=['GET'])   
def get_single_user(user_id):
    user = User.query.filter_by(id=user_id).one()
    return respond_success_data(user.to_dict()),200
    
    
'''Get all the scan history in the application'''
@auth.login_required(role='admin')
@dashboard_routes.route('/scan-history', methods=['GET'])
def get_all_scan_history():
    scan_list = []
    for scan in ScanHistory.query.all():
            scan_list.append(scan.to_dict())
    
    return jsonify(respond_success_data(data=scan_list, message="Sucessfully crawled scan history"))
    

'''Get reports about current running pe model'''
@auth.login_required(role='admin')
@dashboard_routes.route('/model-reports', methods=['GET'])
def get_current_pe_model_report():
    reports = Training.query.filter_by(dataset_for="pe_file").order_by(Training.created_at.desc()).first()
    #Convert into json
    result = ast.literal_eval(reports.results)
    ##Return the model report information 
    return respond_success_data(result, message="Displaying model reports")

'''Get reports about current running pe model'''
@auth.login_required(role='admin')
@dashboard_routes.route('/url-model-reports', methods=['GET'])
def get_current_url_model_report():
    reports = Training.query.filter_by(dataset_for="url").order_by(Training.created_at.desc()).first()
    #Convert into json
    result = ast.literal_eval(reports.results)
    ##Return the model report information 
    return respond_success_data(result, message="Displaying model reports")
    

@dashboard_routes.route('/list-models', methods=['GET'])
def list_all_trained_models():
    train = Training.query.all()
    results = [
        {
            'model_file': entry.model_file,
            'dataset_for': entry.dataset_for,
            'classification_report': entry.classification_report,
            'training_results': entry.training_results,
            'results': entry.results
        } for entry in train
    ]
    return results
