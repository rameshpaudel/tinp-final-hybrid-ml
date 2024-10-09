import datetime
from utils.main import BaseModel, db

'''Displays the scan history of each files and their result'''
class ScanHistory(BaseModel):
    id = db.Column(db.Integer, primary_key=True)
    file_name = db.Column(db.String(150), index=True)
    hashed_name = db.Column(db.String(250), nullable=True)
    file_size = db.Column(db.String(15),nullable=True)
    status = db.Column(db.String(15), nullable=True)
    results = db.Column(db.String(150), nullable=True)
    details = db.Column(db.JSON, nullable=True)
    request_info = db.Column(db.JSON, nullable=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.datetime.now())
    
    _default_fields = [
        "file_name",
        "hashed_name",
        "file_size",
        "status",
        "results",
        "details",
        "request_info",
        "user_id",
        "created_at",
    ]
    
    _readonly_fields = [
        "user_id",
        "created_at"
    ]