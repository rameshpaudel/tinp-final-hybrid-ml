
import jwt
import datetime
from flask import jsonify, g, request, current_app, Blueprint
# werkzug allows -> headers, query args, form data, files, and cookies
from models.user import User, LoginHistory
from utils.main import db, auth

webapp = Blueprint("frontend_pages", __name__)

##Routes
@webapp.route('/scan_file', methods=['POST'])
def scan_file():
    return "Response from the malware scan"
    
@webapp.route('/scan_url', methods=['POST'])
def scan_url():
    return {
        "malware_analysed" : 200,
        "total_scans": 300
    }

