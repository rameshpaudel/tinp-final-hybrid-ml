
import jwt
import datetime
from flask import jsonify, g, request, current_app, Blueprint
# werkzug allows -> headers, query args, form data, files, and cookies

from models.user import User, LoginHistory
from utils.main import db, auth

dashboard_routes = Blueprint("dashboard_routes", __name__, url_prefix="/dashboard")

##Routes
@dashboard_routes.route('/stats', methods=['GET'])
def dash_stats():
    return {
        "malware_analysed" : 200,
        "total_scans": 300
    }

