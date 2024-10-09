
import jwt
import datetime
from flask import jsonify, g, request, current_app, Blueprint
from utils.api_response import response_with_message

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
        "total_scans": 300
    }

'''Get the users list'''
@auth.login_required(role='admin') 
@dashboard_routes.route('/users', methods=['GET'])   
def get_users():
    users_list = []
    for user in User.query.all():
            users_list.append(user.to_dict())
    return response_with_message(data=users_list),200

'''Get individual user's information when id is provided '''
@auth.login_required(role='admin')
@dashboard_routes.route('/user/<int:user_id>', methods=['GET'])   
def get_single_user(user_id):
    user = User.query.filter_by(id=user_id).one()
    return response_with_message(user.to_dict()),200
    
    
'''Get all the scan history in the application'''
@auth.login_required(role='admin')
@dashboard_routes.route('/scan-history', methods=['GET'])
def get_all_scan_history():
    scan_list = []
    for scan in ScanHistory.query.all():
            scan_list.append(scan.to_dict())
    
    return jsonify(response_with_message(data=scan_list, message="Sucessfully crawled scan history"))
    
